"""Core PasskeyProvider for pysskey.

Implements:
  - ``validate_origin``  — Origin/RP-ID validation helper.
  - ``PasskeyProvider``  — Orchestrator for WebAuthn ``create()`` and ``get()``.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import cbor2

from .authenticator_data import (
    AT,
    UP,
    UV,
    build_client_data_json,
    pack_attested_credential_data,
    pack_authenticator_data,
)
from .crypto import generate_keypair, sign_payload
from .exceptions import (
    CredentialExcludedError,
    NoCredentialsFoundError,
    OriginMismatchError,
    UnsupportedAlgorithmError,
    UserVerificationError,
)
from .models import (
    AuthenticationResponse,
    CredentialRecord,
    RegistrationResponse,
    b64url_decode,
    b64url_encode,
)
from .store import CredentialStore

# COSE algorithm identifiers (duplicated here for clarity; same as in crypto.py)
_ALG_ES256 = -7
_ALG_EDDSA = -8
_SUPPORTED_ALGS = [_ALG_ES256, _ALG_EDDSA]  # preference order


# ---------------------------------------------------------------------------
# Origin validation
# ---------------------------------------------------------------------------

def validate_origin(origin: str, rp_id: str) -> bool:
    """Return ``True`` when *origin* is a permitted origin for *rp_id*.

    Rules (WebAuthn §7.1 / §7.2):
    1. Scheme must be ``https``, **or** the origin must be exactly
       ``http://localhost`` (with an optional port component).
    2. The origin hostname must either **equal** *rp_id* exactly, **or**
       be a *registrable subdomain* of *rp_id* — i.e. the hostname ends
       with ``"." + rp_id``.

    Args:
        origin: The ``origin`` string supplied by the client application,
                e.g. ``"https://login.example.com"`` or
                ``"http://localhost:8080"``.
        rp_id:  The Relying Party identifier, e.g. ``"example.com"``.

    Returns:
        ``True`` if the origin satisfies both scheme and domain constraints,
        ``False`` otherwise.
    """
    try:
        parsed = urlparse(origin)
    except Exception:
        return False

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    # ------------------------------------------------------------------ #
    # 1. Scheme check                                                      #
    # ------------------------------------------------------------------ #
    if scheme == "https":
        pass  # always acceptable scheme
    elif scheme == "http" and hostname == "localhost":
        pass  # http://localhost (with or without port) is the only exception
    else:
        return False

    # ------------------------------------------------------------------ #
    # 2. Domain / subdomain check                                          #
    # ------------------------------------------------------------------ #
    rp_id_lower = rp_id.lower()

    # Exact match
    if hostname == rp_id_lower:
        return True

    # Subdomain match: hostname must end with ".<rp_id>"
    if hostname.endswith("." + rp_id_lower):
        return True

    return False


# ---------------------------------------------------------------------------
# PasskeyProvider
# ---------------------------------------------------------------------------

class PasskeyProvider:
    """Authenticator that implements WebAuthn ``create()`` and ``get()``.

    Args:
        store:       Backend used to persist and retrieve credentials.
        aaguid:      16-byte Authenticator Attestation GUID.  Defaults to
                     all-zero bytes (anonymous authenticator).
        up_callback: Optional callable ``(rp_id: str, action: str) -> bool``
                     invoked to obtain User Presence confirmation.  When
                     ``None``, UP is auto-approved (returns ``True``).
        uv_callback: Optional callable ``(rp_id: str) -> bool`` invoked to
                     obtain User Verification.  When ``None``, UV is
                     auto-approved (returns ``True``).
    """

    def __init__(
        self,
        store: CredentialStore,
        aaguid: bytes = b"\x00" * 16,
        up_callback: Optional[Callable[[str, str], bool]] = None,
        uv_callback: Optional[Callable[[str], bool]] = None,
    ) -> None:
        if len(aaguid) != 16:
            raise ValueError(f"aaguid must be exactly 16 bytes, got {len(aaguid)}")

        self._store = store
        self._aaguid = aaguid
        self._up_callback = up_callback
        self._uv_callback = uv_callback

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_origin(self, origin: str, rp_id: str) -> None:
        """Raise :class:`~pysskey.exceptions.OriginMismatchError` when invalid."""
        if not validate_origin(origin, rp_id):
            raise OriginMismatchError(
                f"Origin {origin!r} is not permitted for rp_id {rp_id!r}."
            )

    @staticmethod
    def _to_bytes(value: "bytes | str") -> bytes:
        """Normalise a field that may be raw bytes or a base64url string to bytes.

        WebAuthn options pass ``challenge`` and ``user.id`` as either raw bytes
        (when constructed in Python) or base64url-encoded strings (when
        deserialised from JSON).
        """
        if isinstance(value, bytes):
            return value
        # Assume base64url string
        return b64url_decode(value)

    def _select_alg(self, pub_key_cred_params: List[Dict[str, Any]]) -> int:
        """Return the first mutually-supported algorithm in preference order.

        Preference: ES256 (``-7``) > EdDSA (``-8``).

        Raises:
            UnsupportedAlgorithmError: If none of the requested algorithms
                                       are supported.
        """
        requested = {p["alg"] for p in pub_key_cred_params if p.get("type") == "public-key"}
        for alg in _SUPPORTED_ALGS:
            if alg in requested:
                return alg
        raise UnsupportedAlgorithmError(
            f"None of the requested algorithms {requested!r} are supported. "
            f"Supported: {_SUPPORTED_ALGS}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(
        self,
        options: Dict[str, Any],
        origin: str,
    ) -> RegistrationResponse:
        """Process ``PublicKeyCredentialCreationOptions`` and return a
        :class:`~pysskey.models.RegistrationResponse`.

        Args:
            options: WebAuthn ``PublicKeyCredentialCreationOptions`` dictionary.
                     Expected keys: ``rp``, ``user``, ``challenge``,
                     ``pubKeyCredParams``, and optionally ``excludeCredentials``,
                     ``authenticatorSelection``, and ``attestation``.
            origin:  The origin of the Relying Party web application, e.g.
                     ``"https://app.example.com"``.

        Returns:
            A :class:`~pysskey.models.RegistrationResponse` containing the
            attestation object and related fields.

        Raises:
            OriginMismatchError:       Origin/RP-ID mismatch.
            CredentialExcludedError:   Credential in ``excludeCredentials``
                                       already present in the store.
            UnsupportedAlgorithmError: No supported algorithm in
                                       ``pubKeyCredParams``.
            UserVerificationError:     UP or UV check denied.
        """
        # ------------------------------------------------------------------ #
        # 1. Extract RP ID and validate origin                                #
        # ------------------------------------------------------------------ #
        rp_id: str = options["rp"]["id"]
        self._check_origin(origin, rp_id)

        # ------------------------------------------------------------------ #
        # 2. Check excludeCredentials                                          #
        # ------------------------------------------------------------------ #
        exclude_creds: List[Dict[str, Any]] = options.get("excludeCredentials", []) or []
        for exc in exclude_creds:
            exc_id = self._to_bytes(exc["id"])
            if self._store.get_credential(rp_id, exc_id) is not None:
                raise CredentialExcludedError(
                    f"Credential {b64url_encode(exc_id)!r} is already registered "
                    f"for rp_id {rp_id!r}."
                )

        # ------------------------------------------------------------------ #
        # 3. Select algorithm                                                  #
        # ------------------------------------------------------------------ #
        alg = self._select_alg(options.get("pubKeyCredParams", []))

        # ------------------------------------------------------------------ #
        # 4. User Presence check                                               #
        # ------------------------------------------------------------------ #
        up_ok = self._up_callback(rp_id, "create") if self._up_callback else True
        if not up_ok:
            raise UserVerificationError(
                f"User presence was denied for rp_id {rp_id!r}."
            )

        # ------------------------------------------------------------------ #
        # 5. User Verification check                                           #
        # ------------------------------------------------------------------ #
        auth_sel: Dict[str, Any] = options.get("authenticatorSelection", {}) or {}
        uv_requirement: str = auth_sel.get("userVerification", "preferred")
        uv_flag_set = False
        if uv_requirement in ("required", "preferred"):
            uv_ok = self._uv_callback(rp_id) if self._uv_callback else True
            if not uv_ok:
                raise UserVerificationError(
                    f"User verification was denied for rp_id {rp_id!r}."
                )
            uv_flag_set = True

        # ------------------------------------------------------------------ #
        # 6. Generate keypair                                                  #
        # ------------------------------------------------------------------ #
        private_key_pem, public_key_cose = generate_keypair(alg)

        # ------------------------------------------------------------------ #
        # 7. Build clientDataJSON                                              #
        # ------------------------------------------------------------------ #
        challenge_bytes = self._to_bytes(options["challenge"])
        client_data_json = build_client_data_json("webauthn.create", challenge_bytes, origin)

        # ------------------------------------------------------------------ #
        # 8. Build authenticatorData with AT flag                             #
        # ------------------------------------------------------------------ #
        credential_id = os.urandom(16)

        attested_cred_data = pack_attested_credential_data(
            self._aaguid, credential_id, public_key_cose
        )

        flags = UP | AT  # User Presence always set; AT required for create
        if uv_flag_set:
            flags |= UV

        auth_data = pack_authenticator_data(
            rp_id=rp_id,
            flags=flags,
            sign_count=0,
            attested_cred_data=attested_cred_data,
        )

        # ------------------------------------------------------------------ #
        # 9. Persist credential record                                         #
        # ------------------------------------------------------------------ #
        user: Dict[str, Any] = options["user"]
        user_id_bytes = self._to_bytes(user["id"])

        record = CredentialRecord(
            credential_id=credential_id,
            rp_id=rp_id,
            user_id=user_id_bytes,
            user_name=user.get("name", ""),
            user_display_name=user.get("displayName", ""),
            alg=alg,
            private_key_pem=private_key_pem,
            public_key_cose=public_key_cose,
            sign_count=0,
            discoverable=True,
        )
        self._store.save_credential(record)

        # ------------------------------------------------------------------ #
        # 10. Build CBOR attestation object                                   #
        # ------------------------------------------------------------------ #
        attestation_format: str = options.get("attestation", "none")

        if attestation_format == "packed":
            # Sign authData || SHA-256(clientDataJSON)
            client_data_hash = hashlib.sha256(client_data_json).digest()
            signed_payload = auth_data + client_data_hash
            sig = sign_payload(private_key_pem, alg, signed_payload)
            att_obj = {
                "fmt": "packed",
                "attStmt": {"alg": alg, "sig": sig},
                "authData": auth_data,
            }
        else:
            # Default: "none" attestation
            att_obj = {
                "fmt": "none",
                "attStmt": {},
                "authData": auth_data,
            }

        attestation_object_bytes = cbor2.dumps(att_obj)

        # ------------------------------------------------------------------ #
        # 11. Return RegistrationResponse                                      #
        # ------------------------------------------------------------------ #
        return RegistrationResponse(
            id=b64url_encode(credential_id),
            raw_id=credential_id,
            client_data_json=client_data_json,
            attestation_object=attestation_object_bytes,
            transports=["internal"],
        )

    def get(
        self,
        options: Dict[str, Any],
        origin: str,
    ) -> AuthenticationResponse:
        """Process ``PublicKeyCredentialRequestOptions`` and return an
        :class:`~pysskey.models.AuthenticationResponse`.

        Args:
            options: WebAuthn ``PublicKeyCredentialRequestOptions`` dictionary.
                     Expected keys: ``rpId``, ``challenge``, and optionally
                     ``allowCredentials`` and ``userVerification``.
            origin:  The origin of the Relying Party web application.

        Returns:
            An :class:`~pysskey.models.AuthenticationResponse` containing the
            assertion signature and related fields.

        Raises:
            OriginMismatchError:     Origin/RP-ID mismatch.
            NoCredentialsFoundError: No matching credentials in the store.
            UserVerificationError:   UP or UV check denied.
        """
        # ------------------------------------------------------------------ #
        # 1. Extract RP ID and validate origin                                #
        # ------------------------------------------------------------------ #
        rp_id: str = options["rpId"]
        self._check_origin(origin, rp_id)

        # ------------------------------------------------------------------ #
        # 2. Credential lookup                                                 #
        # ------------------------------------------------------------------ #
        allow_credentials: List[Dict[str, Any]] = options.get("allowCredentials") or []

        if allow_credentials:
            # Explicit allowCredentials: look up each supplied credential ID
            candidates: List[CredentialRecord] = []
            for entry in allow_credentials:
                cred_id = self._to_bytes(entry["id"])
                record = self._store.get_credential(rp_id, cred_id)
                if record is not None:
                    candidates.append(record)
        else:
            # Empty / absent allowCredentials: discover all resident credentials
            candidates = self._store.get_credentials_by_rp(rp_id)

        # ------------------------------------------------------------------ #
        # 3. Require at least one matching credential                          #
        # ------------------------------------------------------------------ #
        if not candidates:
            raise NoCredentialsFoundError(
                f"No credentials found in store for rp_id {rp_id!r}."
            )

        # ------------------------------------------------------------------ #
        # 4. User Presence check                                               #
        # ------------------------------------------------------------------ #
        up_ok = self._up_callback(rp_id, "get") if self._up_callback else True
        if not up_ok:
            raise UserVerificationError(
                f"User presence was denied for rp_id {rp_id!r}."
            )

        # ------------------------------------------------------------------ #
        # 5. User Verification check                                           #
        # ------------------------------------------------------------------ #
        uv_requirement: str = options.get("userVerification", "preferred")
        uv_flag_set = False
        if uv_requirement in ("required", "preferred"):
            uv_ok = self._uv_callback(rp_id) if self._uv_callback else True
            if not uv_ok:
                raise UserVerificationError(
                    f"User verification was denied for rp_id {rp_id!r}."
                )
            uv_flag_set = True

        # ------------------------------------------------------------------ #
        # 6. Select credential (first match)                                   #
        # ------------------------------------------------------------------ #
        credential = candidates[0]

        # ------------------------------------------------------------------ #
        # 7. Increment sign_count                                              #
        # ------------------------------------------------------------------ #
        new_sign_count = self._store.increment_sign_count(rp_id, credential.credential_id)

        # ------------------------------------------------------------------ #
        # 8. Build clientDataJSON                                              #
        # ------------------------------------------------------------------ #
        challenge_bytes = self._to_bytes(options["challenge"])
        client_data_json = build_client_data_json("webauthn.get", challenge_bytes, origin)

        # ------------------------------------------------------------------ #
        # 9. Build authenticatorData (no AT flag, no attested credential data) #
        # ------------------------------------------------------------------ #
        flags = UP  # User Presence always set; AT is NOT set for assertions
        if uv_flag_set:
            flags |= UV

        auth_data = pack_authenticator_data(
            rp_id=rp_id,
            flags=flags,
            sign_count=new_sign_count,
            attested_cred_data=None,
        )

        # ------------------------------------------------------------------ #
        # 10. Sign authData || SHA-256(clientDataJSON)                         #
        # ------------------------------------------------------------------ #
        client_data_hash = hashlib.sha256(client_data_json).digest()
        signed_payload = auth_data + client_data_hash
        signature = sign_payload(credential.private_key_pem, credential.alg, signed_payload)

        # ------------------------------------------------------------------ #
        # 11. Return AuthenticationResponse                                    #
        # ------------------------------------------------------------------ #
        return AuthenticationResponse(
            id=b64url_encode(credential.credential_id),
            raw_id=credential.credential_id,
            client_data_json=client_data_json,
            authenticator_data=auth_data,
            signature=signature,
            user_handle=credential.user_id,
        )
