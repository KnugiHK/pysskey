"""Unit tests for pysskey.crypto — key generation, signing, and verification."""

import cbor2
import pytest

from pysskey.crypto import generate_keypair, sign_payload, verify_signature
from pysskey.exceptions import UnsupportedAlgorithmError


# =====================================================================
# 1. ES256 (-7) Key Generation
# =====================================================================

class TestGenerateKeypairES256:
    """generate_keypair(-7) produces a valid P-256 / ES256 keypair."""

    def setup_method(self):
        self.priv_pem, self.pub_cose = generate_keypair(-7)
        self.cose_map = cbor2.loads(self.pub_cose)

    def test_private_key_is_pem(self):
        assert self.priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert b"-----END PRIVATE KEY-----" in self.priv_pem

    def test_cose_kty_is_ec2(self):
        # COSE key type 2 = EC2
        assert self.cose_map[1] == 2

    def test_cose_alg_is_es256(self):
        assert self.cose_map[3] == -7

    def test_cose_crv_is_p256(self):
        # COSE curve 1 = P-256
        assert self.cose_map[-1] == 1

    def test_cose_x_coordinate_is_32_bytes(self):
        assert isinstance(self.cose_map[-2], bytes)
        assert len(self.cose_map[-2]) == 32

    def test_cose_y_coordinate_is_32_bytes(self):
        assert isinstance(self.cose_map[-3], bytes)
        assert len(self.cose_map[-3]) == 32

    def test_cose_map_contains_required_keys(self):
        # EC2 must carry: 1=kty, 3=alg, -1=crv, -2=x, -3=y
        for key in (1, 3, -1, -2, -3):
            assert key in self.cose_map, f"Missing COSE key {key}"


# =====================================================================
# 2. EdDSA (-8) Key Generation
# =====================================================================

class TestGenerateKeypairEdDSA:
    """generate_keypair(-8) produces a valid Ed25519 / EdDSA keypair."""

    def setup_method(self):
        self.priv_pem, self.pub_cose = generate_keypair(-8)
        self.cose_map = cbor2.loads(self.pub_cose)

    def test_private_key_is_pem(self):
        assert self.priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert b"-----END PRIVATE KEY-----" in self.priv_pem

    def test_cose_kty_is_okp(self):
        # COSE key type 1 = OKP
        assert self.cose_map[1] == 1

    def test_cose_alg_is_eddsa(self):
        assert self.cose_map[3] == -8

    def test_cose_crv_is_ed25519(self):
        # COSE curve 6 = Ed25519
        assert self.cose_map[-1] == 6

    def test_cose_x_is_32_bytes(self):
        assert isinstance(self.cose_map[-2], bytes)
        assert len(self.cose_map[-2]) == 32

    def test_cose_map_contains_required_keys(self):
        # OKP must carry: 1=kty, 3=alg, -1=crv, -2=x  (no -3=y for OKP)
        for key in (1, 3, -1, -2):
            assert key in self.cose_map, f"Missing COSE key {key}"

    def test_cose_map_has_no_y_coordinate(self):
        assert -3 not in self.cose_map


# =====================================================================
# 3. Invalid Algorithm Rejection
# =====================================================================

class TestUnsupportedAlgorithmErrors:
    """generate_keypair, sign_payload, and verify_signature reject unknown algs."""

    UNSUPPORTED = [-257, 0, 1, 999]

    @pytest.mark.parametrize("alg", UNSUPPORTED)
    def test_generate_keypair_raises(self, alg):
        with pytest.raises(UnsupportedAlgorithmError):
            generate_keypair(alg)

    @pytest.mark.parametrize("alg", UNSUPPORTED)
    def test_sign_payload_raises(self, alg):
        # We need a real PEM to get past key loading; use a valid ES256 key.
        priv_pem, _ = generate_keypair(-7)
        with pytest.raises(UnsupportedAlgorithmError):
            sign_payload(priv_pem, alg, b"data")

    @pytest.mark.parametrize("alg", UNSUPPORTED)
    def test_verify_signature_raises(self, alg):
        _, pub_cose = generate_keypair(-7)
        with pytest.raises(UnsupportedAlgorithmError):
            verify_signature(pub_cose, alg, b"data", b"sig")


# =====================================================================
# 4. Round-Trip Signature Verification
# =====================================================================

class TestRoundTripSignature:
    """Sign then verify produces the correct True/False outcomes."""

    DATA = b"webauthn-authenticator-assertion-payload"

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_valid_signature_verifies_true(self, alg):
        priv_pem, pub_cose = generate_keypair(alg)
        sig = sign_payload(priv_pem, alg, self.DATA)
        assert verify_signature(pub_cose, alg, self.DATA, sig) is True

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_tampered_data_verifies_false(self, alg):
        priv_pem, pub_cose = generate_keypair(alg)
        sig = sign_payload(priv_pem, alg, self.DATA)
        assert verify_signature(pub_cose, alg, b"tampered-data", sig) is False

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_tampered_signature_verifies_false(self, alg):
        priv_pem, pub_cose = generate_keypair(alg)
        sig = sign_payload(priv_pem, alg, self.DATA)
        # Flip the last byte of the signature
        bad_sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        assert verify_signature(pub_cose, alg, self.DATA, bad_sig) is False

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_wrong_key_verifies_false(self, alg):
        priv_pem, _ = generate_keypair(alg)
        _, other_pub_cose = generate_keypair(alg)
        sig = sign_payload(priv_pem, alg, self.DATA)
        assert verify_signature(other_pub_cose, alg, self.DATA, sig) is False

    @pytest.mark.parametrize("alg", [-7, -8])
    def test_empty_data_round_trip(self, alg):
        priv_pem, pub_cose = generate_keypair(alg)
        sig = sign_payload(priv_pem, alg, b"")
        assert verify_signature(pub_cose, alg, b"", sig) is True
        assert verify_signature(pub_cose, alg, b"notempty", sig) is False


# =====================================================================
# 5. sign_payload key-type mismatch guards
# =====================================================================

class TestSignPayloadKeyTypeMismatch:
    """sign_payload raises UnsupportedAlgorithmError when the PEM key type
    does not match the requested algorithm (e.g. an EdDSA key with alg=-7)."""

    DATA = b"test-payload"

    def test_eddsa_key_with_es256_alg_raises(self):
        # Generate an EdDSA key but try to sign with ES256
        eddsa_pem, _ = generate_keypair(-8)
        with pytest.raises(UnsupportedAlgorithmError):
            sign_payload(eddsa_pem, -7, self.DATA)

    def test_es256_key_with_eddsa_alg_raises(self):
        # Generate an ES256 key but try to sign with EdDSA
        es256_pem, _ = generate_keypair(-7)
        with pytest.raises(UnsupportedAlgorithmError):
            sign_payload(es256_pem, -8, self.DATA)
