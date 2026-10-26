"""Unit tests for pysskey/models.py — base64url utilities and response dataclasses."""

import pytest

from pysskey.models import (
    AuthenticationResponse,
    CredentialRecord,
    RegistrationResponse,
    b64url_decode,
    b64url_encode,
)


# ---------------------------------------------------------------------------
# b64url_encode
# ---------------------------------------------------------------------------

class TestB64urlEncode:
    def test_no_padding(self):
        """Encoded output must never contain '=' padding characters."""
        for length in range(1, 20):
            raw = bytes(range(length))
            result = b64url_encode(raw)
            assert "=" not in result

    def test_url_safe_chars(self):
        """Output must only contain URL-safe base64 characters (no '+' or '/')."""
        # Use data known to produce '+' or '/' in standard base64
        raw = b"\xfb\xff\xfe"  # base64: +//+ with standard alphabet
        result = b64url_encode(raw)
        assert "+" not in result
        assert "/" not in result

    def test_known_value(self):
        """Spot-check against a known base64url encoding."""
        # b"Man" -> standard base64 "TWFu" -> same in base64url
        assert b64url_encode(b"Man") == "TWFu"

    def test_empty_bytes(self):
        assert b64url_encode(b"") == ""

    def test_returns_str(self):
        assert isinstance(b64url_encode(b"hello"), str)


# ---------------------------------------------------------------------------
# b64url_decode
# ---------------------------------------------------------------------------

class TestB64urlDecode:
    def test_roundtrip(self):
        """Encode then decode must return the original bytes."""
        raw = b"\x00\xff\xfe\x12\x34\x56\x78\x9a"
        assert b64url_decode(b64url_encode(raw)) == raw

    def test_without_padding(self):
        """Decode must succeed when the input has no '=' padding."""
        # "TWFu" decodes to b"Man" — no padding needed
        assert b64url_decode("TWFu") == b"Man"

    def test_with_padding(self):
        """Decode must also accept inputs that already carry '=' padding."""
        assert b64url_decode("TWFu==") == b"Man"

    def test_url_safe_chars(self):
        """Decoder must handle '-' and '_' (url-safe alphabet), not '+' or '/'."""
        raw = b"\xfb\xff\xfe"
        encoded = b64url_encode(raw)
        assert b64url_decode(encoded) == raw

    def test_empty_string(self):
        assert b64url_decode("") == b""

    def test_missing_one_pad_char(self):
        """One missing pad char should be handled gracefully."""
        # "SGVsbG8=" (Hello) without the trailing '='
        assert b64url_decode("SGVsbG8") == b"Hello"

    def test_returns_bytes(self):
        assert isinstance(b64url_decode("aGk"), bytes)


# ---------------------------------------------------------------------------
# RegistrationResponse.to_dict()
# ---------------------------------------------------------------------------

class TestRegistrationResponseToDict:
    def _make_reg(self, transports=None) -> RegistrationResponse:
        kwargs = dict(
            id="Y3JlZF9pZA",
            raw_id=b"cred_id",
            client_data_json=b'{"type":"webauthn.create"}',
            attestation_object=b"\xa3\x63fmt",
        )
        if transports is not None:
            kwargs["transports"] = transports
        return RegistrationResponse(**kwargs)

    def test_top_level_keys(self):
        d = self._make_reg().to_dict()
        assert set(d.keys()) >= {"id", "rawId", "type", "response", "transports"}

    def test_id_passthrough(self):
        d = self._make_reg().to_dict()
        assert d["id"] == "Y3JlZF9pZA"

    def test_raw_id_b64url_encoded(self):
        d = self._make_reg().to_dict()
        assert d["rawId"] == b64url_encode(b"cred_id")

    def test_type_is_public_key(self):
        assert self._make_reg().to_dict()["type"] == "public-key"

    def test_response_contains_attestation_and_client_data(self):
        d = self._make_reg().to_dict()
        assert "attestationObject" in d["response"]
        assert "clientDataJSON" in d["response"]

    def test_response_values_are_b64url(self):
        reg = self._make_reg()
        d = reg.to_dict()
        assert d["response"]["clientDataJSON"] == b64url_encode(reg.client_data_json)
        assert d["response"]["attestationObject"] == b64url_encode(reg.attestation_object)

    def test_default_transport(self):
        d = self._make_reg().to_dict()
        assert d["transports"] == ["internal"]

    def test_custom_transports(self):
        d = self._make_reg(transports=["usb", "nfc"]).to_dict()
        assert d["transports"] == ["usb", "nfc"]


# ---------------------------------------------------------------------------
# AuthenticationResponse.to_dict()
# ---------------------------------------------------------------------------

class TestAuthenticationResponseToDict:
    def _make_auth(self, user_handle=b"user_123") -> AuthenticationResponse:
        return AuthenticationResponse(
            id="Y3JlZF9pZA",
            raw_id=b"cred_id",
            client_data_json=b'{"type":"webauthn.get"}',
            authenticator_data=b"\x00" * 37,
            signature=b"sig_bytes",
            user_handle=user_handle,
        )

    def test_top_level_keys(self):
        d = self._make_auth().to_dict()
        assert set(d.keys()) >= {"id", "rawId", "type", "response"}

    def test_id_passthrough(self):
        assert self._make_auth().to_dict()["id"] == "Y3JlZF9pZA"

    def test_raw_id_b64url_encoded(self):
        d = self._make_auth().to_dict()
        assert d["rawId"] == b64url_encode(b"cred_id")

    def test_type_is_public_key(self):
        assert self._make_auth().to_dict()["type"] == "public-key"

    def test_response_fields_b64url(self):
        auth = self._make_auth()
        d = auth.to_dict()
        resp = d["response"]
        assert resp["clientDataJSON"] == b64url_encode(auth.client_data_json)
        assert resp["authenticatorData"] == b64url_encode(auth.authenticator_data)
        assert resp["signature"] == b64url_encode(auth.signature)

    def test_user_handle_present_when_set(self):
        d = self._make_auth(user_handle=b"user_123").to_dict()
        assert d["response"]["userHandle"] == b64url_encode(b"user_123")

    def test_user_handle_absent_when_none(self):
        d = self._make_auth(user_handle=None).to_dict()
        assert "userHandle" not in d["response"]


# ---------------------------------------------------------------------------
# CredentialRecord aliases
# ---------------------------------------------------------------------------

class TestCredentialRecordAliases:
    def _make_record(self) -> CredentialRecord:
        return CredentialRecord(
            credential_id=b"cred_id",
            rp_id="example.com",
            user_id=b"user_123",
            user_name="alice@example.com",
            user_display_name="Alice",
            alg=-7,
            private_key_pem=b"-----BEGIN PRIVATE KEY-----\n...",
            public_key_cose=b"\xa5",
            sign_count=5,
        )

    def test_user_handle_alias(self):
        rec = self._make_record()
        assert rec.user_handle == rec.user_id

    def test_private_key_alias(self):
        rec = self._make_record()
        assert rec.private_key == rec.private_key_pem

    def test_algorithm_alias(self):
        rec = self._make_record()
        assert rec.algorithm == rec.alg == -7
