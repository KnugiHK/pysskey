"""Unit tests for PasskeyProvider and validate_origin (task 5.1)."""

from __future__ import annotations

import pytest

from pysskey.exceptions import OriginMismatchError
from pysskey.provider import PasskeyProvider, validate_origin
from pysskey.store import InMemoryStore


# ---------------------------------------------------------------------------
# validate_origin – scheme enforcement
# ---------------------------------------------------------------------------

class TestValidateOriginScheme:
    """Verify that only https:// and http://localhost are accepted."""

    def test_https_exact_match_accepted(self):
        assert validate_origin("https://example.com", "example.com") is True

    def test_http_non_localhost_rejected(self):
        assert validate_origin("http://example.com", "example.com") is False

    def test_ftp_scheme_rejected(self):
        assert validate_origin("ftp://example.com", "example.com") is False

    def test_http_localhost_no_port_accepted(self):
        # http://localhost is the lone exception to the https-only rule
        assert validate_origin("http://localhost", "localhost") is True

    def test_http_localhost_with_port_accepted(self):
        assert validate_origin("http://localhost:8080", "localhost") is True

    def test_http_localhost_subdomain_rejected(self):
        # http://sub.localhost is NOT the exception — must be exactly localhost
        assert validate_origin("http://sub.localhost", "localhost") is False

    def test_https_localhost_accepted(self):
        # https://localhost is fine (https is always OK)
        assert validate_origin("https://localhost", "localhost") is True


# ---------------------------------------------------------------------------
# validate_origin – domain / subdomain matching
# ---------------------------------------------------------------------------

class TestValidateOriginDomain:
    """Verify exact-match and subdomain-match behaviour."""

    def test_exact_rp_id_match(self):
        assert validate_origin("https://example.com", "example.com") is True

    def test_direct_subdomain_accepted(self):
        assert validate_origin("https://login.example.com", "example.com") is True

    def test_deep_subdomain_accepted(self):
        assert validate_origin("https://a.b.example.com", "example.com") is True

    def test_different_domain_rejected(self):
        assert validate_origin("https://evil.com", "example.com") is False

    def test_partial_suffix_not_subdomain_rejected(self):
        # "notexample.com" ends with "example.com" in characters but the
        # hostname is not a *subdomain* — the dot boundary must be present.
        assert validate_origin("https://notexample.com", "example.com") is False

    def test_rp_id_as_subdomain_of_origin_rejected(self):
        # rp_id cannot be *longer* than the hostname
        assert validate_origin("https://com", "example.com") is False

    def test_case_insensitive_hostname(self):
        assert validate_origin("https://EXAMPLE.COM", "example.com") is True

    def test_case_insensitive_rp_id(self):
        assert validate_origin("https://login.EXAMPLE.COM", "example.com") is True

    def test_empty_origin_rejected(self):
        assert validate_origin("", "example.com") is False

    def test_garbage_origin_rejected(self):
        assert validate_origin("not-a-url", "example.com") is False

    def test_non_string_origin_rejected(self):
        # Passing a non-string (e.g. an integer) causes urlparse to raise internally;
        # validate_origin must catch that and return False.
        assert validate_origin(123, "example.com") is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# PasskeyProvider – constructor
# ---------------------------------------------------------------------------

class TestPasskeyProviderInit:
    """Verify that PasskeyProvider.__init__ stores arguments correctly."""

    def _make_store(self) -> InMemoryStore:
        return InMemoryStore()

    def test_default_aaguid_is_sixteen_zero_bytes(self):
        provider = PasskeyProvider(store=self._make_store())
        assert provider._aaguid == b"\x00" * 16

    def test_custom_aaguid_stored(self):
        aaguid = bytes(range(16))
        provider = PasskeyProvider(store=self._make_store(), aaguid=aaguid)
        assert provider._aaguid == aaguid

    def test_invalid_aaguid_length_raises_value_error(self):
        with pytest.raises(ValueError, match="16 bytes"):
            PasskeyProvider(store=self._make_store(), aaguid=b"\x00" * 8)

    def test_callbacks_default_to_none(self):
        provider = PasskeyProvider(store=self._make_store())
        assert provider._up_callback is None
        assert provider._uv_callback is None

    def test_custom_callbacks_stored(self):
        up_cb = lambda rp_id, action: True
        uv_cb = lambda rp_id: True
        provider = PasskeyProvider(
            store=self._make_store(),
            up_callback=up_cb,
            uv_callback=uv_cb,
        )
        assert provider._up_callback is up_cb
        assert provider._uv_callback is uv_cb

    def test_store_stored(self):
        store = self._make_store()
        provider = PasskeyProvider(store=store)
        assert provider._store is store


# ---------------------------------------------------------------------------
# PasskeyProvider – _check_origin integration
# ---------------------------------------------------------------------------

class TestCheckOrigin:
    """Verify that _check_origin raises OriginMismatchError appropriately."""

    def setup_method(self):
        self.provider = PasskeyProvider(store=InMemoryStore())

    def test_valid_origin_does_not_raise(self):
        # Should not raise
        self.provider._check_origin("https://example.com", "example.com")

    def test_invalid_scheme_raises(self):
        with pytest.raises(OriginMismatchError):
            self.provider._check_origin("http://example.com", "example.com")

    def test_domain_mismatch_raises(self):
        with pytest.raises(OriginMismatchError):
            self.provider._check_origin("https://evil.com", "example.com")

    def test_valid_subdomain_does_not_raise(self):
        self.provider._check_origin("https://app.example.com", "example.com")

    def test_error_message_contains_origin_and_rp_id(self):
        with pytest.raises(OriginMismatchError, match="http://evil.com"):
            self.provider._check_origin("http://evil.com", "example.com")


# ===========================================================================
# Comprehensive create() and get() tests
# ===========================================================================

import hashlib
import os

import cbor2
import pytest

from pysskey.authenticator_data import AT, UP, UV
from pysskey.crypto import verify_signature
from pysskey.exceptions import (
    CredentialExcludedError,
    NoCredentialsFoundError,
    UnsupportedAlgorithmError,
    UserVerificationError,
)
from pysskey.models import AuthenticationResponse, RegistrationResponse, b64url_encode


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def make_create_options(
    rp_id: str = "example.com",
    challenge: bytes | None = None,
    algs: list[int] | None = None,
    user_id: bytes | str = b"user-1",
    user_name: str = "alice@example.com",
    user_display_name: str = "Alice",
    exclude_credentials: list | None = None,
    user_verification: str = "preferred",
    attestation: str = "none",
) -> dict:
    """Return a minimal but valid PublicKeyCredentialCreationOptions dict."""
    if challenge is None:
        challenge = os.urandom(32)
    if algs is None:
        algs = [-7]
    return {
        "rp": {"id": rp_id, "name": rp_id},
        "user": {
            "id": user_id,
            "name": user_name,
            "displayName": user_display_name,
        },
        "challenge": challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in algs],
        "excludeCredentials": exclude_credentials or [],
        "authenticatorSelection": {"userVerification": user_verification},
        "attestation": attestation,
    }


def make_get_options(
    rp_id: str = "example.com",
    challenge: bytes | None = None,
    allow_credentials: list | None = None,
    user_verification: str = "preferred",
) -> dict:
    """Return a minimal PublicKeyCredentialRequestOptions dict."""
    if challenge is None:
        challenge = os.urandom(32)
    return {
        "rpId": rp_id,
        "challenge": challenge,
        "allowCredentials": allow_credentials or [],
        "userVerification": user_verification,
    }


@pytest.fixture()
def registered_provider():
    """Return a (provider, store, registration_response) tuple after a successful create()."""
    store = InMemoryStore()
    provider = PasskeyProvider(store=store)
    opts = make_create_options()
    reg = provider.create(opts, origin="https://example.com")
    return provider, store, reg


# ---------------------------------------------------------------------------
# create() – happy paths
# ---------------------------------------------------------------------------

class TestCreateHappyPath:
    def test_es256_returns_registration_response(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options(algs=[-7])
        resp = provider.create(opts, origin="https://example.com")
        assert isinstance(resp, RegistrationResponse)
        assert isinstance(resp.raw_id, bytes)
        assert resp.id == b64url_encode(resp.raw_id)
        assert resp.transports == ["internal"]

    def test_eddsa_returns_registration_response(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options(algs=[-8])
        resp = provider.create(opts, origin="https://example.com")
        assert isinstance(resp, RegistrationResponse)
        assert isinstance(resp.raw_id, bytes)

    def test_client_data_json_is_bytes(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options()
        resp = provider.create(opts, origin="https://example.com")
        import json as _json
        parsed = _json.loads(resp.client_data_json)
        assert parsed["type"] == "webauthn.create"
        assert parsed["origin"] == "https://example.com"

    def test_attestation_object_is_cbor(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options()
        resp = provider.create(opts, origin="https://example.com")
        att_obj = cbor2.loads(resp.attestation_object)
        assert "fmt" in att_obj
        assert "authData" in att_obj
        assert "attStmt" in att_obj


# ---------------------------------------------------------------------------
# create() – flag checks in authData
# ---------------------------------------------------------------------------

class TestCreateAuthDataFlags:
    def _parse_auth_data(self, resp: RegistrationResponse) -> dict:
        from pysskey.authenticator_data import parse_authenticator_data
        att_obj = cbor2.loads(resp.attestation_object)
        return parse_authenticator_data(att_obj["authData"])

    def test_at_flag_always_set(self):
        provider = PasskeyProvider(store=InMemoryStore())
        resp = provider.create(make_create_options(), origin="https://example.com")
        parsed = self._parse_auth_data(resp)
        assert parsed["flags"] & AT, "AT flag must be set during create()"

    def test_up_flag_always_set(self):
        provider = PasskeyProvider(store=InMemoryStore())
        resp = provider.create(make_create_options(), origin="https://example.com")
        parsed = self._parse_auth_data(resp)
        assert parsed["flags"] & UP, "UP flag must be set during create()"

    def test_uv_flag_set_when_required(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options(user_verification="required")
        resp = provider.create(opts, origin="https://example.com")
        parsed = self._parse_auth_data(resp)
        assert parsed["flags"] & UV, "UV flag must be set when userVerification=required"

    def test_uv_flag_set_when_preferred(self):
        # With no uv_callback (auto-approve), UV is also set for "preferred"
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options(user_verification="preferred")
        resp = provider.create(opts, origin="https://example.com")
        parsed = self._parse_auth_data(resp)
        assert parsed["flags"] & UV, "UV flag must be set when userVerification=preferred (auto-approve)"

    def test_uv_flag_not_set_when_discouraged(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options(user_verification="discouraged")
        resp = provider.create(opts, origin="https://example.com")
        parsed = self._parse_auth_data(resp)
        assert not (parsed["flags"] & UV), "UV flag must NOT be set when userVerification=discouraged"


# ---------------------------------------------------------------------------
# create() – attestation format
# ---------------------------------------------------------------------------

class TestCreateAttestationFormat:
    def test_none_attestation_fmt_and_empty_stmt(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options(attestation="none")
        resp = provider.create(opts, origin="https://example.com")
        att_obj = cbor2.loads(resp.attestation_object)
        assert att_obj["fmt"] == "none"
        assert att_obj["attStmt"] == {}

    def test_packed_attestation_fmt_and_signature(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options(attestation="packed")
        resp = provider.create(opts, origin="https://example.com")
        att_obj = cbor2.loads(resp.attestation_object)
        assert att_obj["fmt"] == "packed"
        assert "sig" in att_obj["attStmt"]
        assert isinstance(att_obj["attStmt"]["sig"], bytes)
        assert len(att_obj["attStmt"]["sig"]) > 0

    def test_packed_attestation_signature_is_valid(self):
        """The packed attestation signature should verify against authData || SHA-256(clientDataJSON)."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        opts = make_create_options(attestation="packed")
        resp = provider.create(opts, origin="https://example.com")

        att_obj = cbor2.loads(resp.attestation_object)
        auth_data = att_obj["authData"]
        sig = att_obj["attStmt"]["sig"]
        alg = att_obj["attStmt"]["alg"]

        client_data_hash = hashlib.sha256(resp.client_data_json).digest()
        signed_payload = auth_data + client_data_hash

        # Get the stored credential to retrieve the public key
        raw_id = resp.raw_id
        from pysskey.authenticator_data import parse_authenticator_data
        parsed = parse_authenticator_data(auth_data)
        cred_id_from_auth_data = parsed["credential_id"]
        record = store.get_credential("example.com", cred_id_from_auth_data)
        assert record is not None
        assert verify_signature(record.public_key_cose, alg, signed_payload, sig) is True


# ---------------------------------------------------------------------------
# create() – error states
# ---------------------------------------------------------------------------

class TestCreateErrors:
    def test_origin_mismatch_raises(self):
        provider = PasskeyProvider(store=InMemoryStore())
        with pytest.raises(OriginMismatchError):
            provider.create(make_create_options(), origin="https://evil.com")

    def test_credential_excluded_raises(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        opts = make_create_options()
        reg = provider.create(opts, origin="https://example.com")
        # Second create with same credential in excludeCredentials
        opts2 = make_create_options(
            exclude_credentials=[{"type": "public-key", "id": reg.raw_id}]
        )
        with pytest.raises(CredentialExcludedError):
            provider.create(opts2, origin="https://example.com")

    def test_unsupported_algorithm_raises(self):
        provider = PasskeyProvider(store=InMemoryStore())
        opts = make_create_options(algs=[-257])  # RS256 not supported
        with pytest.raises(UnsupportedAlgorithmError):
            provider.create(opts, origin="https://example.com")

    def test_up_denied_raises_user_verification_error(self):
        provider = PasskeyProvider(
            store=InMemoryStore(),
            up_callback=lambda rp_id, action: False,
        )
        with pytest.raises(UserVerificationError):
            provider.create(make_create_options(), origin="https://example.com")

    def test_uv_denied_required_raises_user_verification_error(self):
        provider = PasskeyProvider(
            store=InMemoryStore(),
            uv_callback=lambda rp_id: False,
        )
        opts = make_create_options(user_verification="required")
        with pytest.raises(UserVerificationError):
            provider.create(opts, origin="https://example.com")


# ---------------------------------------------------------------------------
# create() – input normalisation
# ---------------------------------------------------------------------------

class TestCreateInputNormalisation:
    def test_challenge_as_base64url_string(self):
        provider = PasskeyProvider(store=InMemoryStore())
        raw_challenge = os.urandom(32)
        encoded_challenge = b64url_encode(raw_challenge)
        opts = make_create_options(challenge=encoded_challenge)  # type: ignore[arg-type]
        resp = provider.create(opts, origin="https://example.com")
        import json as _json
        parsed_cdj = _json.loads(resp.client_data_json)
        # The challenge embedded in clientDataJSON must be the base64url of the raw challenge
        assert parsed_cdj["challenge"] == encoded_challenge

    def test_user_id_as_base64url_string(self):
        provider = PasskeyProvider(store=InMemoryStore())
        raw_user_id = b"hello-user-42"
        encoded_user_id = b64url_encode(raw_user_id)
        opts = make_create_options(user_id=encoded_user_id)
        resp = provider.create(opts, origin="https://example.com")
        # After create(), the stored record must have the decoded bytes
        store = provider._store
        record = store.get_credential("example.com", resp.raw_id)
        assert record is not None
        assert record.user_id == raw_user_id

    def test_exclude_credentials_base64url_id(self):
        """excludeCredentials with base64url-encoded id strings are decoded correctly."""
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        # Register once
        reg = provider.create(make_create_options(), origin="https://example.com")
        # Encode the raw_id as base64url string to simulate JSON-decoded options
        encoded_id = b64url_encode(reg.raw_id)
        opts = make_create_options(
            exclude_credentials=[{"type": "public-key", "id": encoded_id}]
        )
        with pytest.raises(CredentialExcludedError):
            provider.create(opts, origin="https://example.com")


# ---------------------------------------------------------------------------
# create() – persistence
# ---------------------------------------------------------------------------

class TestCreatePersistence:
    def test_credential_persisted_in_store(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        opts = make_create_options()
        resp = provider.create(opts, origin="https://example.com")
        record = store.get_credential("example.com", resp.raw_id)
        assert record is not None
        assert record.rp_id == "example.com"
        assert record.credential_id == resp.raw_id

    def test_credential_sign_count_starts_at_zero(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(make_create_options(), origin="https://example.com")
        record = store.get_credential("example.com", resp.raw_id)
        assert record.sign_count == 0

    def test_credential_alg_stored_correctly_es256(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(make_create_options(algs=[-7]), origin="https://example.com")
        record = store.get_credential("example.com", resp.raw_id)
        assert record.alg == -7

    def test_credential_alg_stored_correctly_eddsa(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        resp = provider.create(make_create_options(algs=[-8]), origin="https://example.com")
        record = store.get_credential("example.com", resp.raw_id)
        assert record.alg == -8


# ---------------------------------------------------------------------------
# get() – happy paths
# ---------------------------------------------------------------------------

class TestGetHappyPath:
    def test_with_allow_credentials_returns_auth_response(self, registered_provider):
        provider, store, reg = registered_provider
        opts = make_get_options(
            allow_credentials=[{"type": "public-key", "id": reg.raw_id}]
        )
        resp = provider.get(opts, origin="https://example.com")
        assert isinstance(resp, AuthenticationResponse)
        assert resp.raw_id == reg.raw_id

    def test_resident_key_discovery_empty_allow_credentials(self, registered_provider):
        provider, store, reg = registered_provider
        opts = make_get_options(allow_credentials=[])
        resp = provider.get(opts, origin="https://example.com")
        assert isinstance(resp, AuthenticationResponse)
        assert resp.raw_id == reg.raw_id

    def test_response_id_matches_raw_id(self, registered_provider):
        provider, store, reg = registered_provider
        opts = make_get_options()
        resp = provider.get(opts, origin="https://example.com")
        assert resp.id == b64url_encode(resp.raw_id)

    def test_user_handle_matches_registered_user_id(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        user_id = b"test-user-99"
        opts = make_create_options(user_id=user_id)
        reg = provider.create(opts, origin="https://example.com")
        get_opts = make_get_options()
        auth = provider.get(get_opts, origin="https://example.com")
        assert auth.user_handle == user_id

    def test_client_data_json_type_is_webauthn_get(self, registered_provider):
        import json as _json
        provider, store, reg = registered_provider
        opts = make_get_options()
        resp = provider.get(opts, origin="https://example.com")
        parsed = _json.loads(resp.client_data_json)
        assert parsed["type"] == "webauthn.get"


# ---------------------------------------------------------------------------
# get() – authData flag checks
# ---------------------------------------------------------------------------

class TestGetAuthDataFlags:
    def _get_flags(self, resp: AuthenticationResponse) -> int:
        from pysskey.authenticator_data import parse_authenticator_data
        parsed = parse_authenticator_data(resp.authenticator_data)
        return parsed["flags"]

    def test_up_flag_always_set(self, registered_provider):
        provider, store, reg = registered_provider
        resp = provider.get(make_get_options(), origin="https://example.com")
        assert self._get_flags(resp) & UP

    def test_at_flag_not_set_during_get(self, registered_provider):
        provider, store, reg = registered_provider
        resp = provider.get(make_get_options(), origin="https://example.com")
        assert not (self._get_flags(resp) & AT), "AT flag must NOT be set during get()"

    def test_uv_flag_set_when_required(self, registered_provider):
        provider, store, reg = registered_provider
        opts = make_get_options(user_verification="required")
        resp = provider.get(opts, origin="https://example.com")
        assert self._get_flags(resp) & UV

    def test_uv_flag_not_set_when_discouraged(self, registered_provider):
        provider, store, reg = registered_provider
        opts = make_get_options(user_verification="discouraged")
        resp = provider.get(opts, origin="https://example.com")
        assert not (self._get_flags(resp) & UV)


# ---------------------------------------------------------------------------
# get() – sign count
# ---------------------------------------------------------------------------

class TestGetSignCount:
    def test_sign_count_incremented_in_store(self, registered_provider):
        provider, store, reg = registered_provider
        record_before = store.get_credential("example.com", reg.raw_id)
        assert record_before.sign_count == 0
        provider.get(make_get_options(), origin="https://example.com")
        record_after = store.get_credential("example.com", reg.raw_id)
        assert record_after.sign_count == 1

    def test_sign_count_in_auth_data_matches_store(self, registered_provider):
        from pysskey.authenticator_data import parse_authenticator_data
        provider, store, reg = registered_provider
        resp = provider.get(make_get_options(), origin="https://example.com")
        parsed = parse_authenticator_data(resp.authenticator_data)
        record = store.get_credential("example.com", reg.raw_id)
        assert parsed["sign_count"] == record.sign_count

    def test_sign_count_increments_on_each_get(self, registered_provider):
        provider, store, reg = registered_provider
        for expected_count in range(1, 4):
            provider.get(make_get_options(), origin="https://example.com")
            record = store.get_credential("example.com", reg.raw_id)
            assert record.sign_count == expected_count


# ---------------------------------------------------------------------------
# get() – signature verification
# ---------------------------------------------------------------------------

class TestGetSignatureVerification:
    def test_signature_verifies_with_stored_public_key(self, registered_provider):
        provider, store, reg = registered_provider
        resp = provider.get(make_get_options(), origin="https://example.com")
        record = store.get_credential("example.com", reg.raw_id)
        client_data_hash = hashlib.sha256(resp.client_data_json).digest()
        signed_payload = resp.authenticator_data + client_data_hash
        assert verify_signature(
            record.public_key_cose, record.alg, signed_payload, resp.signature
        ) is True

    def test_tampered_payload_fails_verification(self, registered_provider):
        provider, store, reg = registered_provider
        resp = provider.get(make_get_options(), origin="https://example.com")
        record = store.get_credential("example.com", reg.raw_id)
        tampered_payload = b"totally wrong data"
        assert verify_signature(
            record.public_key_cose, record.alg, tampered_payload, resp.signature
        ) is False

    def test_eddsa_signature_verifies(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        reg = provider.create(make_create_options(algs=[-8]), origin="https://example.com")
        resp = provider.get(make_get_options(), origin="https://example.com")
        record = store.get_credential("example.com", reg.raw_id)
        client_data_hash = hashlib.sha256(resp.client_data_json).digest()
        signed_payload = resp.authenticator_data + client_data_hash
        assert verify_signature(
            record.public_key_cose, record.alg, signed_payload, resp.signature
        ) is True


# ---------------------------------------------------------------------------
# get() – error states
# ---------------------------------------------------------------------------

class TestGetErrors:
    def test_origin_mismatch_raises(self, registered_provider):
        provider, store, reg = registered_provider
        with pytest.raises(OriginMismatchError):
            provider.get(make_get_options(), origin="https://evil.com")

    def test_no_credentials_for_rp_raises(self):
        provider = PasskeyProvider(store=InMemoryStore())
        with pytest.raises(NoCredentialsFoundError):
            provider.get(make_get_options(), origin="https://example.com")

    def test_allow_credentials_specifies_nonexistent_cred_raises(self):
        store = InMemoryStore()
        provider = PasskeyProvider(store=store)
        nonexistent_id = os.urandom(16)
        opts = make_get_options(
            allow_credentials=[{"type": "public-key", "id": nonexistent_id}]
        )
        with pytest.raises(NoCredentialsFoundError):
            provider.get(opts, origin="https://example.com")

    def test_up_denied_raises_user_verification_error(self, registered_provider):
        provider, store, reg = registered_provider
        # Override with a new provider that denies UP
        prov_deny = PasskeyProvider(
            store=store,
            up_callback=lambda rp_id, action: False,
        )
        with pytest.raises(UserVerificationError):
            prov_deny.get(make_get_options(), origin="https://example.com")

    def test_uv_denied_required_raises_user_verification_error(self, registered_provider):
        provider, store, reg = registered_provider
        prov_deny_uv = PasskeyProvider(
            store=store,
            uv_callback=lambda rp_id: False,
        )
        opts = make_get_options(user_verification="required")
        with pytest.raises(UserVerificationError):
            prov_deny_uv.get(opts, origin="https://example.com")


# ---------------------------------------------------------------------------
# get() – input normalisation
# ---------------------------------------------------------------------------

class TestGetInputNormalisation:
    def test_challenge_as_base64url_string(self, registered_provider):
        import json as _json
        provider, store, reg = registered_provider
        raw_challenge = os.urandom(32)
        encoded_challenge = b64url_encode(raw_challenge)
        opts = make_get_options(challenge=encoded_challenge)  # type: ignore[arg-type]
        resp = provider.get(opts, origin="https://example.com")
        parsed_cdj = _json.loads(resp.client_data_json)
        assert parsed_cdj["challenge"] == encoded_challenge

    def test_allow_credentials_with_base64url_id(self, registered_provider):
        provider, store, reg = registered_provider
        encoded_id = b64url_encode(reg.raw_id)
        opts = make_get_options(
            allow_credentials=[{"type": "public-key", "id": encoded_id}]
        )
        resp = provider.get(opts, origin="https://example.com")
        assert resp.raw_id == reg.raw_id
