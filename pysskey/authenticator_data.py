"""Authenticator data and client data JSON construction for pysskey.

This module implements the binary packing and parsing of WebAuthn
``authenticatorData`` structures as specified in W3C WebAuthn Level 2,
§6.1 (Authenticator Data).
"""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Optional

import cbor2

from pysskey.models import b64url_encode

# ---------------------------------------------------------------------------
# Flag bitmask constants (§6.1 Table 1)
# ---------------------------------------------------------------------------

UP = 0x01   # Bit 0 – User Presence
UV = 0x04   # Bit 2 – User Verification
BE = 0x08   # Bit 3 – Backup Eligibility
BS = 0x10   # Bit 4 – Backup State
AT = 0x40   # Bit 6 – Attested Credential Data present

# Aliases with FLAG_ prefix (used by test_harness.py)
FLAG_UP = UP
FLAG_UV = UV
FLAG_BE = BE
FLAG_BS = BS
FLAG_AT = AT


# ---------------------------------------------------------------------------
# Client data JSON builder
# ---------------------------------------------------------------------------

def build_client_data_json(webauthn_type: str, challenge: bytes, origin: str) -> bytes:
    """Build the ``clientDataJSON`` byte string sent to the Relying Party.

    The JSON object follows the ``CollectedClientData`` structure defined in
    WebAuthn §5.8.1.  The challenge is base64url-encoded (without padding)
    before being embedded.  ``crossOrigin`` is always ``false`` (same-origin
    ceremony is assumed).

    Args:
        webauthn_type: Either ``"webauthn.create"`` (registration) or
                       ``"webauthn.get"`` (authentication).
        challenge:     Raw challenge bytes provided by the Relying Party.
        origin:        Full origin of the Relying Party (e.g.
                       ``"https://example.com"``).

    Returns:
        UTF-8 encoded bytes of the compact JSON object.
    """
    payload = {
        "type": webauthn_type,
        "challenge": b64url_encode(challenge),
        "origin": origin,
        "crossOrigin": False,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Attested credential data packer
# ---------------------------------------------------------------------------

def pack_attested_credential_data(
    aaguid: bytes,
    credential_id: bytes,
    public_key_cose: bytes,
) -> bytes:
    """Pack the ``attestedCredentialData`` extension appended to ``authData``.

    Layout (WebAuthn §6.5.2):

    .. code-block:: text

        | aaguid (16 B) | credIdLen (2 B, big-endian) | credId | pubKeyCose |

    Args:
        aaguid:           AAGUID that identifies the authenticator model.
                          **Must be exactly 16 bytes.**
        credential_id:    Raw credential identifier bytes.
        public_key_cose:  CBOR-encoded ``COSE_Key`` for the credential's
                          public key.

    Returns:
        Packed bytes ready to be appended to the authenticator data header.

    Raises:
        ValueError: If *aaguid* is not exactly 16 bytes.
    """
    if len(aaguid) != 16:
        raise ValueError(
            f"aaguid must be exactly 16 bytes, got {len(aaguid)}"
        )

    cred_id_len = struct.pack(">H", len(credential_id))
    return aaguid + cred_id_len + credential_id + public_key_cose


# ---------------------------------------------------------------------------
# Authenticator data packer
# ---------------------------------------------------------------------------

def pack_authenticator_data(
    rp_id: str,
    flags: int,
    sign_count: int,
    attested_cred_data: Optional[bytes] = None,
) -> bytes:
    """Construct the binary ``authenticatorData`` structure.

    Layout (WebAuthn §6.1):

    .. code-block:: text

        | rpIdHash (32 B) | flags (1 B) | signCount (4 B, big-endian) |
        [ attestedCredentialData (variable) ]

    The minimum (header-only) length is **37 bytes**.

    Args:
        rp_id:              Relying Party identifier string (e.g.
                            ``"example.com"``).  Hashed via SHA-256.
        flags:              Bitmask combining :data:`UP`, :data:`UV`,
                            :data:`BE`, :data:`BS`, :data:`AT` as required.
        sign_count:         Signature counter value (unsigned 32-bit integer).
        attested_cred_data: Optional pre-packed attested credential data
                            (output of :func:`pack_attested_credential_data`).
                            If provided, the :data:`AT` flag should be set in
                            *flags*.

    Returns:
        Complete ``authenticatorData`` byte string (≥37 bytes).
    """
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()  # 32 bytes
    header = rp_id_hash + struct.pack(">BI", flags, sign_count)  # 32 + 1 + 4
    if attested_cred_data is not None:
        return header + attested_cred_data
    return header


# ---------------------------------------------------------------------------
# Authenticator data parser
# ---------------------------------------------------------------------------

def parse_authenticator_data(auth_data: bytes) -> dict[str, Any]:
    """Parse a binary ``authenticatorData`` structure into a dictionary.

    When the ``AT`` flag is set the attested credential data section is fully
    decoded:

    * ``aaguid`` – first 16 bytes of the section.
    * ``credential_id`` – variable-length field preceded by a 2-byte
      big-endian length prefix.
    * ``credential_public_key`` – CBOR-decoded ``COSE_Key`` map.

    Args:
        auth_data: Raw ``authenticatorData`` bytes (minimum 37 bytes).

    Returns:
        A dictionary with the following keys:

        * ``rp_id_hash`` (:class:`bytes`, 32 bytes) – SHA-256 hash of the
          RP ID.
        * ``flags`` (:class:`int`) – Raw flags byte.
        * ``sign_count`` (:class:`int`) – Big-endian unsigned 32-bit counter.
        * ``has_attested_cred_data`` (:class:`bool`) – ``True`` when the
          :data:`AT` flag (``0x40``) is set.
        * ``attested_cred_data`` (:class:`bytes` or ``None``) – Raw remaining
          bytes after the 37-byte header when :data:`AT` is set, otherwise
          ``None``.
        * ``aaguid`` (:class:`bytes` or ``None``) – 16-byte AAGUID when
          :data:`AT` is set, otherwise ``None``.
        * ``credential_id`` (:class:`bytes` or ``None``) – Raw credential ID
          when :data:`AT` is set, otherwise ``None``.
        * ``credential_public_key`` (decoded CBOR map or ``None``) – Decoded
          ``COSE_Key`` when :data:`AT` is set, otherwise ``None``.

    Raises:
        ValueError: If *auth_data* is shorter than 37 bytes.
    """
    if len(auth_data) < 37:
        raise ValueError(
            f"authenticatorData must be at least 37 bytes, got {len(auth_data)}"
        )

    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    (sign_count,) = struct.unpack_from(">I", auth_data, 33)
    has_at = bool(flags & AT)

    attested_cred_data: Optional[bytes] = None
    aaguid: Optional[bytes] = None
    credential_id: Optional[bytes] = None
    credential_public_key: Any = None

    if has_at:
        attested_cred_data = auth_data[37:]
        # Decode the attested credential data section
        offset = 0
        aaguid = attested_cred_data[offset:offset + 16]
        offset += 16
        (cred_id_len,) = struct.unpack_from(">H", attested_cred_data, offset)
        offset += 2
        credential_id = attested_cred_data[offset:offset + cred_id_len]
        offset += cred_id_len
        # Remaining bytes are CBOR-encoded COSE_Key
        credential_public_key = cbor2.loads(attested_cred_data[offset:])

    return {
        "rp_id_hash": rp_id_hash,
        "flags": flags,
        "sign_count": sign_count,
        "has_attested_cred_data": has_at,
        "attested_cred_data": attested_cred_data,
        "aaguid": aaguid,
        "credential_id": credential_id,
        "credential_public_key": credential_public_key,
    }
