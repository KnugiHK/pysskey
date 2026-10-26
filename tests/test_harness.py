"""
Standalone unit and integration test suite for pysskey.
Covers all functions across models, crypto, authenticator_data, store, and provider.
"""

import hashlib
import json
import os
from pathlib import Path
import cbor2
import pytest

from pysskey.exceptions import (
    CredentialExcludedError,
    NoCredentialsFoundError,
    OriginMismatchError,
    PysskeyError,
    UnsupportedAlgorithmError,
    UserVerificationError,
)
from pysskey.models import (
    AuthenticationResponse,
    CredentialRecord,
    RegistrationResponse,
    b64url_decode,
    b64url_encode,
)
from pysskey.crypto import (
    generate_keypair,
    sign_payload,
    verify_signature,
)
from pysskey.authenticator_data import (
    FLAG_AT,
    FLAG_BE,
    FLAG_BS,
    FLAG_UP,
    FLAG_UV,
    build_client_data_json,
    pack_attested_credential_data,
    pack_authenticator_data,
    parse_authenticator_data,
)
from pysskey.store import EncryptedFileStore, InMemoryStore
from pysskey.provider import PasskeyProvider, validate_origin


# =====================================================================
# 1. Models & Base64URL Utilities Tests
# =====================================================================

def test_b64url_encode_decode_roundtrip():
    raw = b"\x00\xff\xfe\x12\x34\x56\x78\x9a"
    encoded = b64url_encode(raw)
    assert "=" not in encoded  # WebAuthn base64url omits padding
    assert b64url_decode(encoded) == raw
    # Ensure decoding also works if padding is supplied
    assert b64url_decode(encoded + "==") == raw


def test_registration_and_authentication_response_to_dict():
    reg = RegistrationResponse(
        id="Y3JlZF9pZA",
        raw_id=b"cred_id",
        client_data_json=b'{"type":"webauthn.create"}',
        attestation_object=b"\xa3fmt...",
    )
    reg_dict = reg.to_dict()
    assert reg_dict["id"] == "Y3JlZF9pZA"
    assert reg_dict["type"] == "public-key"
    assert "attestationObject" in reg_dict["response"]

    auth = AuthenticationResponse(
        id="Y3JlZF9pZA",
        raw_id=b"cred_id",
        client_data_json=b'{"type":"webauthn.get"}',
        authenticator_data=b"\x00" * 37,
        signature=b"sig_bytes",
        user_handle=b"user_123",
    )
    auth_dict = auth.to_dict()
    assert auth_dict["id"] == "Y3JlZF9pZA"
    assert auth_dict["response"]["userHandle"] == b64url_encode(b"user_123")


# =====================================================================
# 2. Cryptography & COSE Key Tests
# =====================================================================

@pytest.mark.parametrize("alg", [-7, -8])
def test_generate_keypair_and_sign_verify(alg):
    priv_pem, pub_cose = generate_keypair(alg)
    assert priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    cose_map = cbor2.loads(pub_cose)
    assert cose_map[3] == alg  # COSE alg identifier

    message = b"webauthn-assertion-payload-to-sign"
    signature = sign_payload(priv_pem, alg, message)
    assert verify_signature(pub_cose, alg, message, signature) is True
    assert verify_signature(pub_cose, alg, b"tampered-payload", signature) is False


def test_generate_keypair_unsupported_algorithm():
    with pytest.raises(UnsupportedAlgorithmError):
        generate_keypair(-257)  # RS256 not in supported list (-7, -8)


# =====================================================================
# 3. Authenticator Data & ClientDataJSON Tests
# =====================================================================

def test_build_client_data_json():
    challenge = b"random_challenge_123"
    raw_json = build_client_data_json("webauthn.create", challenge, "https://example.com")
    parsed = json.loads(raw_json.decode("utf-8"))
    assert parsed["type"] == "webauthn.create"
    assert parsed["challenge"] == b64url_encode(challenge)
    assert parsed["origin"] == "https://example.com"
    assert parsed["crossOrigin"] is False


def test_pack_and_parse_authenticator_data():
    aaguid = b"\xaa" * 16
    cred_id = b"my_cred_id_16byt"
    _, pub_cose = generate_keypair(-7)

    attested_data = pack_attested_credential_data(aaguid, cred_id, pub_cose)
    flags = FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE | FLAG_BS
    auth_data = pack_authenticator_data("example.com", flags, 42, attested_data)

    parsed = parse_authenticator_data(auth_data)
    assert parsed["rp_id_hash"] == hashlib.sha256(b"example.com").digest()
    assert parsed["flags"] == flags
    assert parsed["sign_count"] == 42
    assert parsed["aaguid"] == aaguid
    assert parsed["credential_id"] == cred_id
    assert parsed["credential_public_key"] == cbor2.loads(pub_cose)


# =====================================================================
# 4. Credential Store Tests (In-Memory & Encrypted File)
# =====================================================================

def _make_dummy_record(cred_id: bytes = b"cred_1", rp_id: str = "example.com") -> CredentialRecord:
    priv, pub = generate_keypair(-7)
    return CredentialRecord(
        credential_id=cred_id,
        rp_id=rp_id,
        user_id=b"user_1",
        user_name="alice@example.com",
        user_display_name="Alice",
        alg=-7,
        private_key_pem=priv,
        public_key_cose=pub,
        sign_count=0,
    )


def test_in_memory_store_crud():
    store = InMemoryStore()
    rec = _make_dummy_record()
    store.save_credential(rec)

    fetched = store.get_credential("example.com", b"cred_1")
    assert fetched is not None
    assert fetched.user_name == "alice@example.com"

    rp_creds = store.get_credentials_by_rp("example.com")
    assert len(rp_creds) == 1

    new_count = store.increment_sign_count("example.com", b"cred_1")
    assert new_count == 1
    assert store.get_credential("example.com", b"cred_1").sign_count == 1

    assert store.delete_credential("example.com", b"cred_1") is True
    assert store.get_credential("example.com", b"cred_1") is None


def test_encrypted_file_store_persistence_and_wrong_key(tmp_path: Path):
    vault_file = tmp_path / "vault.enc"
    store1 = EncryptedFileStore(vault_file, passphrase="correct-horse-battery-staple")
    store1.save_credential(_make_dummy_record(b"cred_persisted"))

    # Re-open from disk with same passphrase
    store2 = EncryptedFileStore(vault_file, passphrase="correct-horse-battery-staple")
    loaded = store2.get_credential("example.com", b"cred_persisted")
    assert loaded is not None
    assert loaded.user_name == "alice@example.com"

    # Attempting to open with wrong passphrase must raise PysskeyError
    with pytest.raises(PysskeyError):
        EncryptedFileStore(vault_file, passphrase="wrong-password")


# =====================================================================
# 5. PasskeyProvider End-to-End Tests
# =====================================================================

def test_validate_origin():
    assert validate_origin("https://login.example.com", "example.com") is True
    assert validate_origin("https://example.com", "example.com") is True
    assert validate_origin("http://localhost:8000", "localhost") is True
    assert validate_origin("http://example.com", "example.com") is False  # Requires HTTPS
    assert validate_origin("https://evil-example.com", "example.com") is False


def test_provider_create_and_get_full_cycle():
    store = InMemoryStore()
    provider = PasskeyProvider(
        store=store,
        up_callback=lambda rp, act: True,
        uv_callback=lambda rp: True,
    )

    create_options = {
        "rp": {"id": "example.com", "name": "Example Corp"},
        "user": {
            "id": b"user_abc_123",
            "name": "bob@example.com",
            "displayName": "Bob",
        },
        "challenge": os.urandom(32),
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -8},
        ],
        "excludeCredentials": [],
        "authenticatorSelection": {
            "residentKey": "required",
            "userVerification": "required",
        },
    }

    # 1. Registration (create)
    reg_response = provider.create(create_options, origin="https://app.example.com")
    att_obj = cbor2.loads(reg_response.attestation_object)
    parsed_auth = parse_authenticator_data(att_obj["authData"])
    assert parsed_auth["flags"] & FLAG_UP
    assert parsed_auth["flags"] & FLAG_UV
    assert parsed_auth["flags"] & FLAG_AT

    # 2. Prevent duplicate registration when in excludeCredentials
    create_options["excludeCredentials"] = [{"type": "public-key", "id": reg_response.raw_id}]
    with pytest.raises(CredentialExcludedError):
        provider.create(create_options, origin="https://app.example.com")

    # 3. Authentication (get) with resident key discovery (empty allowCredentials)
    auth_challenge = os.urandom(32)
    get_options = {
        "rpId": "example.com",
        "challenge": auth_challenge,
        "allowCredentials": [],
        "userVerification": "required",
    }
    auth_response = provider.get(get_options, origin="https://app.example.com")
    assert auth_response.raw_id == reg_response.raw_id
    assert auth_response.user_handle == b"user_abc_123"

    # 4. Cryptographically verify the assertion signature just as an RP server would
    stored_cred = store.get_credential("example.com", reg_response.raw_id)
    assert stored_cred.sign_count == 1
    client_data_hash = hashlib.sha256(auth_response.client_data_json).digest()
    signed_data = auth_response.authenticator_data + client_data_hash
    assert verify_signature(
        stored_cred.public_key_cose,
        stored_cred.alg,
        signed_data,
        auth_response.signature,
    ) is True


def test_provider_error_conditions():
    store = InMemoryStore()
    provider = PasskeyProvider(
        store=store,
        up_callback=lambda rp, act: False,  # Deny user presence
    )

    base_create_opts = {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": b"1", "name": "u", "displayName": "U"},
        "challenge": b"1234",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }

    # Origin mismatch
    with pytest.raises(OriginMismatchError):
        provider.create(base_create_opts, origin="https://phishing.com")

    # User presence denied
    with pytest.raises(UserVerificationError):
        provider.create(base_create_opts, origin="https://example.com")

    # No credentials found on get()
    provider_allow_up = PasskeyProvider(store=store, up_callback=lambda r, a: True)
    with pytest.raises(NoCredentialsFoundError):
        provider_allow_up.get(
            {"rpId": "example.com", "challenge": b"1234"},
            origin="https://example.com",
        )


# =====================================================================
# 6. Additional Coverage Tests
# =====================================================================

# --- models.py: CredentialRecord property aliases ---

def test_credential_record_property_aliases():
    priv, pub = generate_keypair(-7)
    rec = CredentialRecord(
        credential_id=b"cred_x",
        rp_id="example.com",
        user_id=b"uid_xyz",
        user_name="test@example.com",
        user_display_name="Test",
        alg=-7,
        private_key_pem=priv,
        public_key_cose=pub,
        sign_count=3,
    )
    assert rec.user_handle == b"uid_xyz"
    assert rec.private_key == priv
    assert rec.algorithm == -7


# --- authenticator_data.py: ValueError paths ---

def test_pack_attested_credential_data_bad_aaguid():
    with pytest.raises(ValueError, match="16 bytes"):
        pack_attested_credential_data(b"\xaa" * 15, b"cred", b"cose")


def test_parse_authenticator_data_too_short():
    with pytest.raises(ValueError, match="37 bytes"):
        parse_authenticator_data(b"\x00" * 36)


# --- crypto.py: sign_payload unsupported alg + wrong key type guards ---

def test_sign_payload_unsupported_algorithm():
    priv_pem, _ = generate_keypair(-7)
    with pytest.raises(UnsupportedAlgorithmError):
        sign_payload(priv_pem, -257, b"data")


def test_sign_payload_wrong_key_type_es256_with_eddsa_key():
    """Pass an EdDSA key while requesting ES256 → wrong-type guard fires."""
    ed_priv_pem, _ = generate_keypair(-8)
    with pytest.raises(UnsupportedAlgorithmError, match="EC private key"):
        sign_payload(ed_priv_pem, -7, b"data")


def test_sign_payload_wrong_key_type_eddsa_with_ec_key():
    """Pass an EC key while requesting EdDSA → wrong-type guard fires."""
    ec_priv_pem, _ = generate_keypair(-7)
    with pytest.raises(UnsupportedAlgorithmError, match="Ed25519 private key"):
        sign_payload(ec_priv_pem, -8, b"data")


def test_verify_signature_unsupported_algorithm():
    _, pub_cose = generate_keypair(-7)
    with pytest.raises(UnsupportedAlgorithmError):
        verify_signature(pub_cose, -257, b"data", b"sig")


# --- store.py: InMemoryStore edge cases ---

def test_in_memory_store_increment_missing_credential():
    store = InMemoryStore()
    with pytest.raises(KeyError):
        store.increment_sign_count("example.com", b"nonexistent")


def test_in_memory_store_delete_nonexistent():
    store = InMemoryStore()
    result = store.delete_credential("example.com", b"nonexistent")
    assert result is False


# --- store.py: EncryptedFileStore corrupted vault ---

def test_encrypted_file_store_corrupted_vault(tmp_path: Path):
    vault_file = tmp_path / "bad_vault.enc"
    vault_file.write_text("not valid json at all", encoding="utf-8")
    with pytest.raises(PysskeyError):
        EncryptedFileStore(vault_file, passphrase="any-passphrase")


def test_encrypted_file_store_get_credentials_by_rp(tmp_path: Path):
    vault_file = tmp_path / "vault_rp.enc"
    store = EncryptedFileStore(vault_file, passphrase="pass")
    store.save_credential(_make_dummy_record(b"c1", "example.com"))
    store.save_credential(_make_dummy_record(b"c2", "other.com"))
    creds = store.get_credentials_by_rp("example.com")
    assert len(creds) == 1
    assert creds[0].credential_id == b"c1"


def test_encrypted_file_store_increment_and_delete(tmp_path: Path):
    vault_file = tmp_path / "vault_ops.enc"
    store = EncryptedFileStore(vault_file, passphrase="pass")
    store.save_credential(_make_dummy_record(b"cred_op"))

    new_count = store.increment_sign_count("example.com", b"cred_op")
    assert new_count == 1

    result = store.delete_credential("example.com", b"cred_op")
    assert result is True
    assert store.get_credential("example.com", b"cred_op") is None

    # delete a second time → False
    result2 = store.delete_credential("example.com", b"cred_op")
    assert result2 is False


# --- provider.py: validate_origin exception branch ---

def test_validate_origin_exception_branch():
    # urlparse on an ordinary bad string doesn't throw, so we monkeypatch
    import pysskey.provider as prov_mod
    from unittest.mock import patch

    with patch("pysskey.provider.urlparse", side_effect=Exception("parse error")):
        assert prov_mod.validate_origin("https://example.com", "example.com") is False


# --- provider.py: PasskeyProvider bad aaguid ---

def test_provider_bad_aaguid():
    store = InMemoryStore()
    with pytest.raises(ValueError, match="16 bytes"):
        PasskeyProvider(store=store, aaguid=b"\x00" * 15)


# --- provider.py: create() with packed attestation format ---

def test_provider_create_packed_attestation():
    store = InMemoryStore()
    provider = PasskeyProvider(store=store)

    options = {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": b"user_1", "name": "u@example.com", "displayName": "U"},
        "challenge": os.urandom(32),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "attestation": "packed",
    }
    response = provider.create(options, origin="https://example.com")
    att_obj = cbor2.loads(response.attestation_object)
    assert att_obj["fmt"] == "packed"
    assert "sig" in att_obj["attStmt"]


# --- provider.py: create() UV denied ---

def test_provider_create_uv_denied():
    store = InMemoryStore()
    provider = PasskeyProvider(
        store=store,
        up_callback=lambda rp, act: True,
        uv_callback=lambda rp: False,
    )
    options = {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": b"u1", "name": "u", "displayName": "U"},
        "challenge": b"ch",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"userVerification": "required"},
    }
    with pytest.raises(UserVerificationError):
        provider.create(options, origin="https://example.com")


# --- provider.py: get() with explicit allowCredentials (hit and miss) ---

def _register_credential(provider, store, rp_id="example.com", origin=None):
    """Helper: register one credential and return the RegistrationResponse."""
    if origin is None:
        origin = f"https://{rp_id}"
    options = {
        "rp": {"id": rp_id, "name": "RP"},
        "user": {"id": os.urandom(8), "name": "u@test.com", "displayName": "U"},
        "challenge": os.urandom(32),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }
    return provider.create(options, origin=origin)


def test_provider_get_with_explicit_allow_credentials():
    store = InMemoryStore()
    provider = PasskeyProvider(store=store)
    reg = _register_credential(provider, store)

    get_options = {
        "rpId": "example.com",
        "challenge": os.urandom(32),
        "allowCredentials": [{"type": "public-key", "id": reg.raw_id}],
        "userVerification": "preferred",
    }
    auth_resp = provider.get(get_options, origin="https://example.com")
    assert auth_resp.raw_id == reg.raw_id


def test_provider_get_with_allow_credentials_no_match():
    """allowCredentials supplied but none match → NoCredentialsFoundError."""
    store = InMemoryStore()
    provider = PasskeyProvider(store=store)
    _register_credential(provider, store)

    get_options = {
        "rpId": "example.com",
        "challenge": os.urandom(32),
        "allowCredentials": [{"type": "public-key", "id": b"nonexistent_id_x"}],
    }
    with pytest.raises(NoCredentialsFoundError):
        provider.get(get_options, origin="https://example.com")


# --- provider.py: get() UP denied ---

def test_provider_get_up_denied():
    store = InMemoryStore()
    # Register with a permissive provider first
    reg_provider = PasskeyProvider(store=store)
    _register_credential(reg_provider, store)

    get_provider = PasskeyProvider(store=store, up_callback=lambda rp, act: False)
    with pytest.raises(UserVerificationError):
        get_provider.get(
            {"rpId": "example.com", "challenge": os.urandom(32), "allowCredentials": []},
            origin="https://example.com",
        )


# --- provider.py: get() UV denied ---

def test_provider_get_uv_denied():
    store = InMemoryStore()
    reg_provider = PasskeyProvider(store=store)
    _register_credential(reg_provider, store)

    get_provider = PasskeyProvider(
        store=store,
        up_callback=lambda rp, act: True,
        uv_callback=lambda rp: False,
    )
    with pytest.raises(UserVerificationError):
        get_provider.get(
            {
                "rpId": "example.com",
                "challenge": os.urandom(32),
                "allowCredentials": [],
                "userVerification": "required",
            },
            origin="https://example.com",
        )


# --- provider.py: _to_bytes with base64url string + _select_alg unsupported ---

def test_provider_create_with_base64url_challenge_and_user_id():
    """Exercises the _to_bytes str→bytes branch for challenge and user.id."""
    from pysskey.models import b64url_encode
    store = InMemoryStore()
    provider = PasskeyProvider(store=store)
    raw_challenge = os.urandom(32)
    raw_user_id = b"usr_b64"
    options = {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {
            "id": b64url_encode(raw_user_id),   # str, not bytes
            "name": "u@example.com",
            "displayName": "U",
        },
        "challenge": b64url_encode(raw_challenge),  # str, not bytes
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }
    response = provider.create(options, origin="https://example.com")
    stored = store.get_credential("example.com", response.raw_id)
    assert stored.user_id == raw_user_id


def test_provider_create_unsupported_algorithm_in_params():
    """_select_alg raises UnsupportedAlgorithmError when no alg matches."""
    store = InMemoryStore()
    provider = PasskeyProvider(store=store)
    options = {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": b"u", "name": "u", "displayName": "U"},
        "challenge": b"ch",
        "pubKeyCredParams": [{"type": "public-key", "alg": -257}],
    }
    with pytest.raises(UnsupportedAlgorithmError):
        provider.create(options, origin="https://example.com")
