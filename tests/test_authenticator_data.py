"""Unit tests for pysskey/authenticator_data.py.

Covers:
- build_client_data_json: structure, base64url challenge, crossOrigin field
- pack_attested_credential_data: byte layout, aaguid length validation
- pack_authenticator_data: 37-byte header, big-endian sign_count, flag bitmasks,
  optional attested credential data appended
- parse_authenticator_data: round-trip parsing, AT flag detection, aaguid/cred_id
  extraction, ValueError on short input
"""

from __future__ import annotations

import hashlib
import json
import struct

import cbor2
import pytest

from pysskey.authenticator_data import (
    AT,
    BE,
    BS,
    FLAG_AT,
    FLAG_BE,
    FLAG_BS,
    FLAG_UP,
    FLAG_UV,
    UP,
    UV,
    build_client_data_json,
    pack_attested_credential_data,
    pack_authenticator_data,
    parse_authenticator_data,
)
from pysskey.models import b64url_encode


# ---------------------------------------------------------------------------
# build_client_data_json
# ---------------------------------------------------------------------------

class TestBuildClientDataJson:
    def test_returns_bytes(self):
        result = build_client_data_json("webauthn.create", b"challenge", "https://example.com")
        assert isinstance(result, bytes)

    def test_utf8_encoded(self):
        result = build_client_data_json("webauthn.create", b"challenge", "https://example.com")
        # Should be valid UTF-8
        result.decode("utf-8")

    def test_json_fields_present(self):
        challenge = b"\x01\x02\x03\x04"
        origin = "https://example.com"
        result = build_client_data_json("webauthn.create", challenge, origin)
        parsed = json.loads(result.decode("utf-8"))
        assert parsed["type"] == "webauthn.create"
        assert parsed["challenge"] == b64url_encode(challenge)
        assert parsed["origin"] == origin

    def test_challenge_is_base64url_no_padding(self):
        # Use bytes that would produce padding when base64-encoded
        challenge = b"\xfb\xff\xfe"
        result = build_client_data_json("webauthn.get", challenge, "https://example.com")
        parsed = json.loads(result.decode("utf-8"))
        assert "=" not in parsed["challenge"]
        assert b64url_encode(challenge) == parsed["challenge"]

    def test_cross_origin_is_false(self):
        result = build_client_data_json("webauthn.create", b"c", "https://example.com")
        parsed = json.loads(result.decode("utf-8"))
        assert parsed["crossOrigin"] is False

    def test_webauthn_get_type(self):
        result = build_client_data_json("webauthn.get", b"chal", "https://login.example.com")
        parsed = json.loads(result.decode("utf-8"))
        assert parsed["type"] == "webauthn.get"


# ---------------------------------------------------------------------------
# pack_attested_credential_data
# ---------------------------------------------------------------------------

class TestPackAttestedCredentialData:
    def test_layout_aaguid_credidlen_credid_pubkey(self):
        aaguid = b"\xaa" * 16
        cred_id = b"test_credential_id"
        pub_key_cose = b"\xa5\x01\x02"  # minimal CBOR stub
        result = pack_attested_credential_data(aaguid, cred_id, pub_key_cose)

        # First 16 bytes: aaguid
        assert result[:16] == aaguid
        # Next 2 bytes: big-endian length of credential_id
        (cred_id_len,) = struct.unpack_from(">H", result, 16)
        assert cred_id_len == len(cred_id)
        # Credential id bytes
        assert result[18:18 + cred_id_len] == cred_id
        # Remaining: COSE key
        assert result[18 + cred_id_len:] == pub_key_cose

    def test_total_length(self):
        aaguid = b"\x00" * 16
        cred_id = b"abc"
        pub_key_cose = b"\x01\x02\x03\x04"
        result = pack_attested_credential_data(aaguid, cred_id, pub_key_cose)
        expected_len = 16 + 2 + len(cred_id) + len(pub_key_cose)
        assert len(result) == expected_len

    def test_aaguid_wrong_length_raises(self):
        with pytest.raises(ValueError, match="16 bytes"):
            pack_attested_credential_data(b"\x00" * 15, b"cred", b"\x01")

    def test_aaguid_too_long_raises(self):
        with pytest.raises(ValueError, match="16 bytes"):
            pack_attested_credential_data(b"\x00" * 17, b"cred", b"\x01")

    def test_empty_credential_id(self):
        aaguid = b"\x00" * 16
        result = pack_attested_credential_data(aaguid, b"", b"\xff")
        (cred_id_len,) = struct.unpack_from(">H", result, 16)
        assert cred_id_len == 0
        assert result[18:] == b"\xff"


# ---------------------------------------------------------------------------
# pack_authenticator_data
# ---------------------------------------------------------------------------

class TestPackAuthenticatorData:
    RP_ID = "example.com"

    def test_minimum_37_bytes(self):
        result = pack_authenticator_data(self.RP_ID, UP, 0)
        assert len(result) == 37

    def test_rp_id_hash_correct(self):
        result = pack_authenticator_data(self.RP_ID, UP, 0)
        expected_hash = hashlib.sha256(self.RP_ID.encode("utf-8")).digest()
        assert result[:32] == expected_hash

    def test_flags_byte_at_offset_32(self):
        for flag in (UP, UV, BE, BS, AT):
            result = pack_authenticator_data(self.RP_ID, flag, 0)
            assert result[32] == flag

    def test_combined_flags(self):
        flags = UP | UV | AT
        result = pack_authenticator_data(self.RP_ID, flags, 0)
        assert result[32] == flags

    def test_sign_count_big_endian_at_offset_33(self):
        result = pack_authenticator_data(self.RP_ID, UP, 0x00010203)
        (sign_count,) = struct.unpack_from(">I", result, 33)
        assert sign_count == 0x00010203

    def test_sign_count_zero(self):
        result = pack_authenticator_data(self.RP_ID, UP, 0)
        assert result[33:37] == b"\x00\x00\x00\x00"

    def test_sign_count_max(self):
        result = pack_authenticator_data(self.RP_ID, UP, 0xFFFFFFFF)
        (sign_count,) = struct.unpack_from(">I", result, 33)
        assert sign_count == 0xFFFFFFFF

    def test_with_attested_cred_data_appended(self):
        aaguid = b"\xbb" * 16
        cred_id = b"my_cred"
        pub_key_cose = b"\xa1\x01\x01"
        attested = pack_attested_credential_data(aaguid, cred_id, pub_key_cose)
        result = pack_authenticator_data(self.RP_ID, UP | AT, 1, attested)
        assert len(result) == 37 + len(attested)
        assert result[37:] == attested

    def test_without_attested_cred_data_no_extra_bytes(self):
        result = pack_authenticator_data(self.RP_ID, UP, 5, None)
        assert len(result) == 37

    def test_flag_constants_aliases(self):
        """FLAG_* aliases must equal their short-name counterparts."""
        assert FLAG_UP == UP
        assert FLAG_UV == UV
        assert FLAG_BE == BE
        assert FLAG_BS == BS
        assert FLAG_AT == AT


# ---------------------------------------------------------------------------
# parse_authenticator_data
# ---------------------------------------------------------------------------

class TestParseAuthenticatorData:
    RP_ID = "example.com"

    def _make_auth_data(
        self,
        flags: int = UP,
        sign_count: int = 0,
        attested: bytes | None = None,
    ) -> bytes:
        return pack_authenticator_data(self.RP_ID, flags, sign_count, attested)

    def test_raises_on_short_input(self):
        with pytest.raises(ValueError, match="37 bytes"):
            parse_authenticator_data(b"\x00" * 36)

    def test_rp_id_hash(self):
        auth_data = self._make_auth_data()
        result = parse_authenticator_data(auth_data)
        assert result["rp_id_hash"] == hashlib.sha256(self.RP_ID.encode()).digest()
        assert len(result["rp_id_hash"]) == 32

    def test_flags_roundtrip(self):
        flags = UP | UV | AT | BE | BS
        auth_data = self._make_auth_data(flags=flags)
        # supply attested data so AT flag is consistent
        aaguid = b"\x00" * 16
        attested = pack_attested_credential_data(aaguid, b"cred", b"\xa0")
        auth_data = self._make_auth_data(flags=flags, attested=attested)
        result = parse_authenticator_data(auth_data)
        assert result["flags"] == flags

    def test_sign_count_roundtrip(self):
        for count in (0, 1, 42, 0xFFFFFFFF):
            auth_data = self._make_auth_data(sign_count=count)
            result = parse_authenticator_data(auth_data)
            assert result["sign_count"] == count

    def test_no_attested_cred_data_when_at_not_set(self):
        auth_data = self._make_auth_data(flags=UP)
        result = parse_authenticator_data(auth_data)
        assert result["has_attested_cred_data"] is False
        assert result["attested_cred_data"] is None
        assert result["aaguid"] is None
        assert result["credential_id"] is None
        assert result["credential_public_key"] is None

    def test_attested_cred_data_present_when_at_set(self):
        aaguid = b"\xcc" * 16
        cred_id = b"credential_id_test"
        # Build a minimal CBOR COSE key map: {1: 2}
        cose_key = cbor2.dumps({1: 2})
        attested = pack_attested_credential_data(aaguid, cred_id, cose_key)
        auth_data = self._make_auth_data(flags=UP | AT, attested=attested)
        result = parse_authenticator_data(auth_data)

        assert result["has_attested_cred_data"] is True
        assert result["attested_cred_data"] == attested
        assert result["aaguid"] == aaguid
        assert result["credential_id"] == cred_id
        assert result["credential_public_key"] == {1: 2}

    def test_round_trip_preserves_all_fields(self):
        """Pack then parse should produce consistent values."""
        aaguid = b"\xde\xad\xbe\xef" * 4
        cred_id = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        cose_key = cbor2.dumps({1: 1, 3: -8, -1: 6, -2: b"\xab" * 32})
        attested = pack_attested_credential_data(aaguid, cred_id, cose_key)
        flags = UP | UV | AT
        sign_count = 99

        auth_data = pack_authenticator_data(self.RP_ID, flags, sign_count, attested)
        result = parse_authenticator_data(auth_data)

        assert result["rp_id_hash"] == hashlib.sha256(self.RP_ID.encode()).digest()
        assert result["flags"] == flags
        assert result["sign_count"] == sign_count
        assert result["has_attested_cred_data"] is True
        assert result["aaguid"] == aaguid
        assert result["credential_id"] == cred_id
        assert result["credential_public_key"] == cbor2.loads(cose_key)

    def test_exactly_37_bytes_accepted(self):
        auth_data = b"\x00" * 37
        result = parse_authenticator_data(auth_data)
        assert result["sign_count"] == 0
        assert result["flags"] == 0
        assert result["has_attested_cred_data"] is False
