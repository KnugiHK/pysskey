"""Cryptographic primitives and COSE_Key encoding for pysskey."""

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from pysskey.exceptions import UnsupportedAlgorithmError

# COSE algorithm identifiers
ALG_ES256 = -7   # ECDSA with P-256 and SHA-256
ALG_EDDSA = -8   # EdDSA with Ed25519


def generate_keypair(alg: int) -> tuple[bytes, bytes]:
    """Generate a keypair for the given COSE algorithm identifier.

    Args:
        alg: COSE algorithm identifier. Supported values: -7 (ES256), -8 (EdDSA).

    Returns:
        A tuple of (private_key_pem, public_key_cose) where private_key_pem is
        the PEM-encoded private key bytes and public_key_cose is the CBOR-encoded
        COSE_Key map bytes.

    Raises:
        UnsupportedAlgorithmError: If alg is not -7 or -8.
    """
    if alg == ALG_ES256:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Encode private key as PKCS8 PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Encode public key as COSE_Key CBOR map (EC2 key type)
        pub_numbers = public_key.public_numbers()
        x_bytes = pub_numbers.x.to_bytes(32, "big")
        y_bytes = pub_numbers.y.to_bytes(32, "big")

        cose_key = {
            1: 2,       # kty: EC2
            3: ALG_ES256,  # alg: ES256
            -1: 1,      # crv: P-256
            -2: x_bytes,   # x coordinate
            -3: y_bytes,   # y coordinate
        }
        public_key_cose = cbor2.dumps(cose_key)
        return private_key_pem, public_key_cose

    elif alg == ALG_EDDSA:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Encode private key as PKCS8 PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Encode public key as COSE_Key CBOR map (OKP key type)
        x_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        cose_key = {
            1: 1,       # kty: OKP
            3: ALG_EDDSA,  # alg: EdDSA
            -1: 6,      # crv: Ed25519
            -2: x_bytes,   # public key bytes (32 bytes)
        }
        public_key_cose = cbor2.dumps(cose_key)
        return private_key_pem, public_key_cose

    else:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {alg}. Supported values are -7 (ES256) and -8 (EdDSA)."
        )


def sign_payload(private_key_pem: bytes, alg: int, data: bytes) -> bytes:
    """Sign data using the given algorithm and PEM-encoded private key.

    Args:
        private_key_pem: PEM-encoded private key bytes.
        alg: COSE algorithm identifier. Supported values: -7 (ES256), -8 (EdDSA).
        data: The raw bytes to sign.

    Returns:
        For alg=-7: DER-encoded ECDSA signature bytes.
        For alg=-8: Raw 64-byte Ed25519 signature bytes.

    Raises:
        UnsupportedAlgorithmError: If alg is not -7 or -8.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    if alg == ALG_ES256:
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise UnsupportedAlgorithmError("Expected an EC private key for ES256.")
        signature = private_key.sign(data, ECDSA(hashes.SHA256()))
        return signature  # DER-encoded by default

    elif alg == ALG_EDDSA:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise UnsupportedAlgorithmError("Expected an Ed25519 private key for EdDSA.")
        signature = private_key.sign(data)
        return signature  # Raw 64-byte signature

    else:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {alg}. Supported values are -7 (ES256) and -8 (EdDSA)."
        )


def verify_signature(
    public_key_cose: bytes, alg: int, data: bytes, signature: bytes
) -> bool:
    """Verify a signature against data using a COSE_Key encoded public key.

    Args:
        public_key_cose: CBOR-encoded COSE_Key map bytes.
        alg: COSE algorithm identifier. Supported values: -7 (ES256), -8 (EdDSA).
        data: The raw bytes that were signed.
        signature: The signature bytes to verify.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        UnsupportedAlgorithmError: If alg is not -7 or -8.
    """
    cose_map = cbor2.loads(public_key_cose)

    if alg == ALG_ES256:
        x_bytes = cose_map[-2]
        y_bytes = cose_map[-3]
        x = int.from_bytes(x_bytes, "big")
        y = int.from_bytes(y_bytes, "big")

        pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
        public_key = pub_numbers.public_key()

        try:
            public_key.verify(signature, data, ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    elif alg == ALG_EDDSA:
        x_bytes = cose_map[-2]
        public_key = Ed25519PublicKey.from_public_bytes(x_bytes)

        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    else:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {alg}. Supported values are -7 (ES256) and -8 (EdDSA)."
        )
