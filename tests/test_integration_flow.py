"""End-to-end integration tests for pysskey.

Simulates full WebAuthn Relying Party challenge-response cycles — registration
followed by authentication — and cryptographically verifies every output using
``pysskey.crypto.verify_signature``.

Coverage targets (task 6.1):
* Full registration flow (create) for ES256 (-7) and EdDSA (-8)
* Full authentication flow (get) for ES256 (-7) and EdDSA (-8)
* End-to-end cycle: register then authenticate with the same credential
* Attestation signature verification for ``"packed"`` format
* Assertion signature verification
* clientDataJSON structure and challenge round-trip
* authData flag correctness (UP, UV, AT)
* sign_count monotonically increments across multiple authentications
* Resident-key (discoverable credential) discovery flow
* Subdomain origin / cross-subdomain registration + authentication
"""

from __future__ import annotations

import hashlib
import json
import os

import cbor2
import pytest

from pysskey.authenticator_data import AT, UP, UV, parse_authenticator_data
from pysskey.crypto import verify_signature
from pysskey.exceptions import (
    CredentialExcludedError,
    NoCredentialsFoundError,
    OriginMismatchError,
)
from pysskey.models import (
    AuthenticationResponse,
    RegistrationResponse,
    b64url_decode,
    b64url_encode,
)
from pysskey.provider import PasskeyProvider
from pysskey.store import InMemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RP_ID = "example.com"
_ORIGIN = "https://example.com"
_SUBDOMAIN_ORIGIN = "https://app.example.com"


def _create_options(
    *,
    rp_id: str = _RP_ID,
    algs: list[int] | None = None,
    user_id: bytes = b"integration-user-1",
    user_name: str = "alice@example.com",
    exclude_credentials: list | None = None,
    user_verification: str = "required",
    attestation: str = "none",
    challenge: bytes | None = None,
) -> dict:
    """Build a minimal ``PublicKeyCredentialCreationOptions`` dict."""
    if algs is None:
        algs = [-7]
    if challenge is None:
        challenge = os.urandom(32)
    return {
        "rp": {"id": rp_id, "name": rp_id.capitalize()},
        "user": {
            "id": user_id,
            "name": user_name,
            "displayName": user_name.split("@")[0].capitalize(),
        },
        "challenge": challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in algs],
        "excludeCredentials": exclude_credentials or [],
        "authenticatorSelection": {"userVerification": user_verification},
        "attestation": attestation,
    }


def _get_options(
    *,
    rp_id: str = _RP_ID,
    allow_credentials: list | None = None,
    user_verification: str = "required",
    challenge: bytes | None = None,
) -> dict:
    """Build a minimal ``PublicKeyCredentialRequestOptions`` dict."""
    if challenge is None:
        challenge = os.urandom(32)
    return {
        "rpId": rp_id,
        "challenge": challenge,
        "allowCredentials": allow_credentials or [],
        "userVerification": user_verification,
    }


def _verify_assertion(
    store: InMemoryStore,
    rp_id: str,
    resp: AuthenticationResponse,
) -> bool:
    """Replicate the RP-side assertion verification step."""
    record = store.get_credential(rp_id, resp.raw_id)
    assert record is not None, "Credential must exist in store"
    client_data_hash = hashlib.sha256(resp.client_data_json).digest()
    signed_payload = resp.authenticator_data + client_data_hash
    return verify_signature(record.public_key_cose, record.alg, signed_payload, resp.signature)


def _verify_packed_attestation(
    store: InMemoryStore,
    rp_id: str,
    resp: RegistrationResponse,
) -> bool:
    """Replicate the RP-side packed-attestation verification step."""
    att_obj = cbor2.loads(resp.attestation_object)
    auth_data: bytes = att_obj["authData"]
    sig: bytes = att_obj["attStmt"]["sig"]
    alg: int = att_obj["attStmt"]["alg"]
    client_data_hash = hashlib.sha256(resp.client_data_json).digest()
    signed_payload = auth_data + client_data_hash
    # Retrieve public key from the attested credential data inside authData
    parsed = parse_authenticator_data(auth_data)
    record = store.get_credential(rp_id, parsed["credential_id"])
    assert record is not None
    return verify_signature(record.public_key_cose, alg, signed_payload, sig)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def provider_es256():
    """A PasskeyProvider backed by InMemoryStore, auto-approves UP and UV."""
    store = InMemoryStore()
    provider = PasskeyProvider(store=store)
    return provider, store


@pytest.fixture()
def provider_eddsa():
    store = InMemoryStore()
    provider = PasskeyProvider(store=store)
    return provider, store


@pytest.fixture()
def registered_es256(provider_es256):
    """Provider, store, and RegistrationResponse for a pre-registered ES256 credential."""
    provider, store = provider_es256
    opts = _create_options(algs=[-7])
    reg = provider.create(opts, origin=_ORIGIN)
    return provider, store, reg


@pytest.fixture()
def registered_eddsa(provider_eddsa):
    """Provider, store, and RegistrationResponse for a pre-registered EdDSA credential."""
    provider, store = provider_eddsa
    opts = _create_options(algs=[-8])
    reg = provider.create(opts, origin=_ORIGIN)
    return provider, store, reg


# ===========================================================================
# 1. Registration (create) – structural verification
# ===========================================================================

class TestRegistrationStructure:
    """Verify that create() returns a structurally valid RegistrationResponse."""

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_response_types(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)
        assert isinstance(resp, RegistrationResponse)
        assert isinstance(resp.raw_id, bytes) and len(resp.raw_id) > 0
        assert isinstance(resp.client_data_json, bytes)
        assert isinstance(resp.attestation_object, bytes)
        assert resp.transports == ["internal"]

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_id_is_base64url_of_raw_id(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)
        assert resp.id == b64url_encode(resp.raw_id)
        # base64url must have no padding characters
        assert "=" not in resp.id

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_client_data_json_structure(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        raw_challenge = os.urandom(32)
        resp = provider.create(
            _create_options(algs=[alg], challenge=raw_challenge),
            origin=_ORIGIN,
        )
        cdj = json.loads(resp.client_data_json)
        assert cdj["type"] == "webauthn.create"
        assert cdj["origin"] == _ORIGIN
        assert cdj["crossOrigin"] is False
        # Challenge must round-trip through base64url
        assert b64url_decode(cdj["challenge"]) == raw_challenge

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_attestation_object_is_valid_cbor(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)
        att_obj = cbor2.loads(resp.attestation_object)
        assert set(att_obj.keys()) >= {"fmt", "attStmt", "authData"}
        assert att_obj["fmt"] == "none"
        assert att_obj["attStmt"] == {}
        assert isinstance(att_obj["authData"], bytes)
        assert len(att_obj["authData"]) >= 37


# ===========================================================================
# 2. Registration (create) – authData verification
# ===========================================================================

class TestRegistrationAuthData:
    """Verify authData flags, structure, and embedded credential data."""

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_up_and_at_flags_set(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)
        att_obj = cbor2.loads(resp.attestation_object)
        parsed = parse_authenticator_data(att_obj["authData"])
        assert parsed["flags"] & UP, "UP flag must be set during create()"
        assert parsed["flags"] & AT, "AT flag must be set during create()"

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_uv_flag_set_when_required(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(
            _create_options(algs=[alg], user_verification="required"),
            origin=_ORIGIN,
        )
        att_obj = cbor2.loads(resp.attestation_object)
        parsed = parse_authenticator_data(att_obj["authData"])
        assert parsed["flags"] & UV, "UV flag must be set when userVerification=required"

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_sign_count_starts_at_zero(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)
        att_obj = cbor2.loads(resp.attestation_object)
        parsed = parse_authenticator_data(att_obj["authData"])
        assert parsed["sign_count"] == 0

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_rp_id_hash_correct(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)
        att_obj = cbor2.loads(resp.attestation_object)
        parsed = parse_authenticator_data(att_obj["authData"])
        expected_hash = hashlib.sha256(_RP_ID.encode("utf-8")).digest()
        assert parsed["rp_id_hash"] == expected_hash

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_credential_id_in_auth_data_matches_response(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)
        att_obj = cbor2.loads(resp.attestation_object)
        parsed = parse_authenticator_data(att_obj["authData"])
        assert parsed["credential_id"] == resp.raw_id

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_public_key_in_auth_data_verifies_signature(self, alg):
        """The COSE public key embedded in authData must verify get() assertions."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)

        # Extract public key directly from authData (as an RP would)
        att_obj = cbor2.loads(resp.attestation_object)
        parsed_reg = parse_authenticator_data(att_obj["authData"])
        # The credential_public_key from authData is the decoded CBOR map; re-encode for verify_signature
        pub_key_cose_from_auth_data = cbor2.dumps(parsed_reg["credential_public_key"])

        # Now authenticate
        auth_resp = provider.get(_get_options(), origin=_ORIGIN)
        client_data_hash = hashlib.sha256(auth_resp.client_data_json).digest()
        signed_payload = auth_resp.authenticator_data + client_data_hash

        assert verify_signature(
            pub_key_cose_from_auth_data, alg, signed_payload, auth_resp.signature
        ) is True


# ===========================================================================
# 3. Registration (create) – packed attestation verification
# ===========================================================================

class TestRegistrationPackedAttestation:
    """Verify packed attestation signatures produced during create()."""

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_packed_attestation_fmt_and_fields(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(
            _create_options(algs=[alg], attestation="packed"),
            origin=_ORIGIN,
        )
        att_obj = cbor2.loads(resp.attestation_object)
        assert att_obj["fmt"] == "packed"
        assert "sig" in att_obj["attStmt"]
        assert "alg" in att_obj["attStmt"]
        assert att_obj["attStmt"]["alg"] == alg
        assert isinstance(att_obj["attStmt"]["sig"], bytes)
        assert len(att_obj["attStmt"]["sig"]) > 0

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_packed_attestation_signature_verifies(self, alg):
        """RP-side packed attestation verification: sig covers authData || SHA256(clientDataJSON)."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(
            _create_options(algs=[alg], attestation="packed"),
            origin=_ORIGIN,
        )
        assert _verify_packed_attestation(store, _RP_ID, resp) is True

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_tampered_packed_attestation_fails(self, alg):
        """Altering authData must invalidate the packed attestation signature."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(
            _create_options(algs=[alg], attestation="packed"),
            origin=_ORIGIN,
        )
        att_obj = cbor2.loads(resp.attestation_object)
        sig = att_obj["attStmt"]["sig"]
        alg_val = att_obj["attStmt"]["alg"]
        # Tamper: flip last byte of authData
        tampered_auth_data = att_obj["authData"][:-1] + bytes([att_obj["authData"][-1] ^ 0xFF])
        client_data_hash = hashlib.sha256(resp.client_data_json).digest()
        tampered_payload = tampered_auth_data + client_data_hash

        parsed = parse_authenticator_data(att_obj["authData"])
        record = store.get_credential(_RP_ID, parsed["credential_id"])
        assert verify_signature(record.public_key_cose, alg_val, tampered_payload, sig) is False


# ===========================================================================
# 4. Authentication (get) – structural verification
# ===========================================================================

class TestAuthenticationStructure:
    """Verify that get() returns a structurally valid AuthenticationResponse."""

    @pytest.mark.parametrize("alg,fixture_name", [(-7, "registered_es256"), (-8, "registered_eddsa")])
    def test_response_types(self, alg, fixture_name, registered_es256, registered_eddsa):
        fixture = registered_es256 if alg == -7 else registered_eddsa
        provider, store, reg = fixture
        resp = provider.get(_get_options(), origin=_ORIGIN)
        assert isinstance(resp, AuthenticationResponse)
        assert isinstance(resp.raw_id, bytes)
        assert isinstance(resp.authenticator_data, bytes) and len(resp.authenticator_data) >= 37
        assert isinstance(resp.signature, bytes) and len(resp.signature) > 0
        assert isinstance(resp.client_data_json, bytes)

    def test_id_is_base64url_of_raw_id(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        assert resp.id == b64url_encode(resp.raw_id)
        assert "=" not in resp.id

    def test_client_data_json_type_is_webauthn_get(self, registered_es256):
        provider, store, reg = registered_es256
        raw_challenge = os.urandom(32)
        resp = provider.get(_get_options(challenge=raw_challenge), origin=_ORIGIN)
        cdj = json.loads(resp.client_data_json)
        assert cdj["type"] == "webauthn.get"
        assert cdj["origin"] == _ORIGIN
        assert cdj["crossOrigin"] is False
        assert b64url_decode(cdj["challenge"]) == raw_challenge

    def test_user_handle_matches_registered_user_id(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        record = store.get_credential(_RP_ID, resp.raw_id)
        assert resp.user_handle == record.user_id


# ===========================================================================
# 5. Authentication (get) – authData verification
# ===========================================================================

class TestAuthenticationAuthData:
    """Verify authData flags and sign_count during authentication."""

    def test_up_flag_set_and_at_flag_not_set(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        parsed = parse_authenticator_data(resp.authenticator_data)
        assert parsed["flags"] & UP, "UP flag must be set during get()"
        assert not (parsed["flags"] & AT), "AT flag must NOT be set during get()"

    def test_uv_flag_set_when_required(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(user_verification="required"), origin=_ORIGIN)
        parsed = parse_authenticator_data(resp.authenticator_data)
        assert parsed["flags"] & UV

    def test_uv_flag_not_set_when_discouraged(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(user_verification="discouraged"), origin=_ORIGIN)
        parsed = parse_authenticator_data(resp.authenticator_data)
        assert not (parsed["flags"] & UV)

    def test_rp_id_hash_correct_in_assertion(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        parsed = parse_authenticator_data(resp.authenticator_data)
        expected_hash = hashlib.sha256(_RP_ID.encode("utf-8")).digest()
        assert parsed["rp_id_hash"] == expected_hash

    def test_sign_count_in_auth_data_matches_store(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        parsed = parse_authenticator_data(resp.authenticator_data)
        record = store.get_credential(_RP_ID, resp.raw_id)
        assert parsed["sign_count"] == record.sign_count == 1


# ===========================================================================
# 6. Signature verification – core goal
# ===========================================================================

class TestSignatureVerification:
    """Cryptographically verify assertion signatures — the primary RP concern."""

    def test_es256_assertion_signature_verifies(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        assert _verify_assertion(store, _RP_ID, resp) is True

    def test_eddsa_assertion_signature_verifies(self, registered_eddsa):
        provider, store, reg = registered_eddsa
        resp = provider.get(_get_options(), origin=_ORIGIN)
        assert _verify_assertion(store, _RP_ID, resp) is True

    def test_tampered_auth_data_fails_verification(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        record = store.get_credential(_RP_ID, resp.raw_id)
        tampered_auth_data = resp.authenticator_data[:-1] + bytes([resp.authenticator_data[-1] ^ 0xFF])
        client_data_hash = hashlib.sha256(resp.client_data_json).digest()
        tampered_payload = tampered_auth_data + client_data_hash
        assert verify_signature(record.public_key_cose, record.alg, tampered_payload, resp.signature) is False

    def test_tampered_client_data_hash_fails_verification(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        record = store.get_credential(_RP_ID, resp.raw_id)
        tampered_hash = bytes([b ^ 0xFF for b in hashlib.sha256(resp.client_data_json).digest()])
        tampered_payload = resp.authenticator_data + tampered_hash
        assert verify_signature(record.public_key_cose, record.alg, tampered_payload, resp.signature) is False

    def test_wrong_signature_fails_verification(self, registered_es256):
        provider, store, reg = registered_es256
        resp = provider.get(_get_options(), origin=_ORIGIN)
        record = store.get_credential(_RP_ID, resp.raw_id)
        client_data_hash = hashlib.sha256(resp.client_data_json).digest()
        payload = resp.authenticator_data + client_data_hash
        wrong_sig = bytes([b ^ 0x01 for b in resp.signature])
        assert verify_signature(record.public_key_cose, record.alg, payload, wrong_sig) is False


# ===========================================================================
# 7. Full end-to-end cycle (register → authenticate)
# ===========================================================================

class TestEndToEndCycle:
    """Register a credential and authenticate with it — both algorithms."""

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_register_then_authenticate_signature_verifies(self, alg):
        """Core E2E: register, then authenticate, then verify the assertion signature."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)

        # Registration
        reg = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)
        assert isinstance(reg, RegistrationResponse)

        # Authentication
        auth = provider.get(_get_options(), origin=_ORIGIN)
        assert isinstance(auth, AuthenticationResponse)
        assert auth.raw_id == reg.raw_id

        # Cryptographic verification (RP-side)
        assert _verify_assertion(store, _RP_ID, auth) is True

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_sign_count_increments_across_multiple_authentications(self, alg):
        """sign_count must increase by 1 per authentication."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        provider.create(_create_options(algs=[alg]), origin=_ORIGIN)

        for expected_count in range(1, 5):
            auth = provider.get(_get_options(), origin=_ORIGIN)
            parsed = parse_authenticator_data(auth.authenticator_data)
            assert parsed["sign_count"] == expected_count
            # Signature must still verify at every increment
            assert _verify_assertion(store, _RP_ID, auth) is True

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_explicit_allow_credentials_lookup(self, alg):
        """Authentication with an explicit allowCredentials list."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        reg = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)

        auth = provider.get(
            _get_options(allow_credentials=[{"type": "public-key", "id": reg.raw_id}]),
            origin=_ORIGIN,
        )
        assert auth.raw_id == reg.raw_id
        assert _verify_assertion(store, _RP_ID, auth) is True

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_resident_key_discovery(self, alg):
        """Authentication with an empty allowCredentials list triggers resident key discovery."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        reg = provider.create(_create_options(algs=[alg]), origin=_ORIGIN)

        auth = provider.get(_get_options(allow_credentials=[]), origin=_ORIGIN)
        assert auth.raw_id == reg.raw_id
        assert _verify_assertion(store, _RP_ID, auth) is True

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_packed_attestation_verify_then_authenticate(self, alg):
        """Register with packed attestation, verify it, then authenticate and verify assertion."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)

        reg = provider.create(_create_options(algs=[alg], attestation="packed"), origin=_ORIGIN)
        # Step 1: RP verifies packed attestation
        assert _verify_packed_attestation(store, _RP_ID, reg) is True

        # Step 2: RP issues a challenge and authenticates
        auth = provider.get(_get_options(), origin=_ORIGIN)
        assert _verify_assertion(store, _RP_ID, auth) is True


# ===========================================================================
# 8. Multi-credential and multi-user scenarios
# ===========================================================================

class TestMultiCredential:
    """Verify correct isolation between multiple registered credentials."""

    def test_two_users_same_rp_get_different_credentials(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)

        reg1 = provider.create(
            _create_options(user_id=b"user-1", user_name="alice@example.com"),
            origin=_ORIGIN,
        )
        reg2 = provider.create(
            _create_options(user_id=b"user-2", user_name="bob@example.com"),
            origin=_ORIGIN,
        )
        assert reg1.raw_id != reg2.raw_id

        # Each credential can authenticate independently
        for raw_id in (reg1.raw_id, reg2.raw_id):
            auth = provider.get(
                _get_options(allow_credentials=[{"type": "public-key", "id": raw_id}]),
                origin=_ORIGIN,
            )
            assert auth.raw_id == raw_id
            assert _verify_assertion(store, _RP_ID, auth) is True

    def test_exclude_credentials_prevents_re_registration(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)

        reg = provider.create(_create_options(), origin=_ORIGIN)
        opts = _create_options(
            exclude_credentials=[{"type": "public-key", "id": reg.raw_id}]
        )
        with pytest.raises(CredentialExcludedError):
            provider.create(opts, origin=_ORIGIN)

    def test_get_with_unknown_credential_id_raises(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)

        # Register a credential so the provider isn't empty, but request a different ID
        provider.create(_create_options(), origin=_ORIGIN)
        unknown_id = os.urandom(16)
        with pytest.raises(NoCredentialsFoundError):
            provider.get(
                _get_options(allow_credentials=[{"type": "public-key", "id": unknown_id}]),
                origin=_ORIGIN,
            )


# ===========================================================================
# 9. Subdomain / cross-origin scenarios
# ===========================================================================

class TestSubdomainOrigin:
    """Verify that a subdomain origin is accepted for the same rp_id."""

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_register_from_subdomain_then_authenticate(self, alg):
        """Credentials created via a subdomain origin are reachable from any valid subdomain."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)

        reg = provider.create(
            _create_options(algs=[alg]),
            origin=_SUBDOMAIN_ORIGIN,  # https://app.example.com
        )
        # Authentication from the same subdomain
        auth = provider.get(_get_options(), origin=_SUBDOMAIN_ORIGIN)
        assert auth.raw_id == reg.raw_id
        assert _verify_assertion(store, _RP_ID, auth) is True

    def test_origin_mismatch_raises_on_create(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        with pytest.raises(OriginMismatchError):
            provider.create(_create_options(), origin="https://evil.com")

    def test_origin_mismatch_raises_on_get(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        provider.create(_create_options(), origin=_ORIGIN)
        with pytest.raises(OriginMismatchError):
            provider.get(_get_options(), origin="https://evil.com")


# ===========================================================================
# 10. clientDataJSON challenge round-trip
# ===========================================================================

class TestChallengeRoundTrip:
    """Ensure challenges survive the full create/get cycle without mutation."""

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_create_challenge_embedded_in_client_data_json(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        raw_challenge = os.urandom(32)
        resp = provider.create(
            _create_options(algs=[alg], challenge=raw_challenge),
            origin=_ORIGIN,
        )
        cdj = json.loads(resp.client_data_json)
        assert b64url_decode(cdj["challenge"]) == raw_challenge

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_get_challenge_embedded_in_client_data_json(self, alg):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        provider.create(_create_options(algs=[alg]), origin=_ORIGIN)

        raw_challenge = os.urandom(32)
        resp = provider.get(_get_options(challenge=raw_challenge), origin=_ORIGIN)
        cdj = json.loads(resp.client_data_json)
        assert b64url_decode(cdj["challenge"]) == raw_challenge

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_base64url_encoded_challenge_accepted_in_options(self, alg):
        """Options carrying a base64url-encoded challenge string are normalised correctly."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        raw_challenge = os.urandom(32)
        encoded_challenge = b64url_encode(raw_challenge)

        # Pass as str (simulates JSON-decoded options)
        resp = provider.create(
            _create_options(algs=[alg], challenge=encoded_challenge),  # type: ignore[arg-type]
            origin=_ORIGIN,
        )
        cdj = json.loads(resp.client_data_json)
        assert cdj["challenge"] == encoded_challenge
