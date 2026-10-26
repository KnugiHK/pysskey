"""Data models and base64url utilities for pysskey."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    """Encode *data* as a base64url string **without** padding characters."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """Decode a base64url string, adding missing padding automatically."""
    # Restore padding: base64 requires length % 4 == 0
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


# ---------------------------------------------------------------------------
# Core credential record (stored by CredentialStore)
# ---------------------------------------------------------------------------

@dataclass
class CredentialRecord:
    """Persisted representation of a single discoverable passkey credential.

    Attributes:
        credential_id:      Raw bytes identifying this credential.
        rp_id:              Relying Party identifier (e.g. ``"example.com"``).
        user_id:            Opaque user handle supplied by the RP (bytes).
        user_name:          Human-readable account name (e.g. email address).
        user_display_name:  Display name shown in account-chooser UI.
        alg:                COSE algorithm identifier (``-7`` ES256, ``-8`` EdDSA).
        private_key_pem:    PEM-encoded private key bytes.
        public_key_cose:    CBOR-encoded COSE_Key map for the public key.
        sign_count:         Monotonically increasing signature counter.
        discoverable:       Whether this is a resident/discoverable credential.
    """

    credential_id: bytes
    rp_id: str
    user_id: bytes
    user_name: str
    user_display_name: str
    alg: int                  # -7 (ES256) or -8 (EdDSA)
    private_key_pem: bytes
    public_key_cose: bytes
    sign_count: int = 0
    discoverable: bool = True

    # Convenience aliases for WebAuthn spec language
    @property
    def user_handle(self) -> bytes:
        """Alias for ``user_id`` (WebAuthn spec terminology)."""
        return self.user_id

    @property
    def private_key(self) -> bytes:
        """Alias for ``private_key_pem``."""
        return self.private_key_pem

    @property
    def algorithm(self) -> int:
        """Alias for ``alg`` (COSE algorithm identifier)."""
        return self.alg


# ---------------------------------------------------------------------------
# Registration response
# ---------------------------------------------------------------------------

@dataclass
class RegistrationResponse:
    """Output of ``PasskeyProvider.create()``.

    Attributes:
        id:                 Base64url-encoded credential ID string.
        raw_id:             Raw credential ID bytes.
        client_data_json:   JSON bytes for ``clientDataJSON``.
        attestation_object: CBOR-encoded attestation object bytes.
        transports:         List of authenticator transport hints.
    """

    id: str
    raw_id: bytes
    client_data_json: bytes
    attestation_object: bytes
    transports: list[str] = field(default_factory=lambda: ["internal"])

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a WebAuthn-compatible wire-format dictionary.

        Byte fields are base64url-encoded; the overall shape mirrors the
        ``PublicKeyCredential`` JSON serialisation described in the
        WebAuthn Level 2 specification.
        """
        return {
            "id": self.id,
            "rawId": b64url_encode(self.raw_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(self.client_data_json),
                "attestationObject": b64url_encode(self.attestation_object),
            },
            "transports": list(self.transports),
        }


# ---------------------------------------------------------------------------
# Authentication response
# ---------------------------------------------------------------------------

@dataclass
class AuthenticationResponse:
    """Output of ``PasskeyProvider.get()``.

    Attributes:
        id:                 Base64url-encoded credential ID string.
        raw_id:             Raw credential ID bytes.
        client_data_json:   JSON bytes for ``clientDataJSON``.
        authenticator_data: Raw authenticator data bytes.
        signature:          Raw assertion signature bytes.
        user_handle:        Opaque user handle bytes, or ``None``.
    """

    id: str
    raw_id: bytes
    client_data_json: bytes
    authenticator_data: bytes
    signature: bytes
    user_handle: Optional[bytes]

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a WebAuthn-compatible wire-format dictionary.

        Byte fields are base64url-encoded. ``userHandle`` is omitted from the
        nested ``response`` map when it is ``None``.
        """
        response: dict[str, Any] = {
            "clientDataJSON": b64url_encode(self.client_data_json),
            "authenticatorData": b64url_encode(self.authenticator_data),
            "signature": b64url_encode(self.signature),
        }
        if self.user_handle is not None:
            response["userHandle"] = b64url_encode(self.user_handle)

        return {
            "id": self.id,
            "rawId": b64url_encode(self.raw_id),
            "type": "public-key",
            "response": response,
        }
