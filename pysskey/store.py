"""Pluggable credential storage for pysskey.

Provides:
  - ``CredentialStore``  — Abstract Base Class defining the storage contract.
  - ``InMemoryStore``    — Thread-safe, dict-backed implementation for testing
                           and single-process use.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

from .models import CredentialRecord


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class CredentialStore(ABC):
    """Contract that every credential storage backend must fulfil."""

    @abstractmethod
    def save_credential(self, record: CredentialRecord) -> None:
        """Persist *record*, overwriting any existing entry with the same key.

        The composite key is ``(rp_id, credential_id)``.
        """

    @abstractmethod
    def get_credential(
        self, rp_id: str, credential_id: bytes
    ) -> Optional[CredentialRecord]:
        """Return the ``CredentialRecord`` for ``(rp_id, credential_id)``,
        or ``None`` if it does not exist.
        """

    @abstractmethod
    def get_credentials_by_rp(self, rp_id: str) -> List[CredentialRecord]:
        """Return every resident credential whose ``rp_id`` matches exactly."""

    @abstractmethod
    def increment_sign_count(self, rp_id: str, credential_id: bytes) -> int:
        """Atomically increment the stored ``sign_count`` by 1.

        Returns the **updated** value.

        Raises ``KeyError`` if the credential does not exist.
        """

    @abstractmethod
    def delete_credential(self, rp_id: str, credential_id: bytes) -> bool:
        """Remove the credential identified by ``(rp_id, credential_id)``.

        Returns ``True`` if the record existed and was deleted, ``False``
        if it was not found.
        """

    @abstractmethod
    def get_all_credentials(self) -> List[CredentialRecord]:
        """Return every credential across all RP IDs."""


# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------

class InMemoryStore(CredentialStore):
    """Volatile, dict-backed ``CredentialStore``.

    All data lives in process memory and is lost when the object is garbage-
    collected.  Suitable for unit tests and single-request demos.
    """

    def __init__(self) -> None:
        # Keyed by (rp_id, credential_id)
        self._store: Dict[Tuple[str, bytes], CredentialRecord] = {}

    # ------------------------------------------------------------------
    # CredentialStore implementation
    # ------------------------------------------------------------------

    def save_credential(self, record: CredentialRecord) -> None:
        """Store *record* under ``(record.rp_id, record.credential_id)``."""
        key = (record.rp_id, record.credential_id)
        self._store[key] = record

    def get_credential(
        self, rp_id: str, credential_id: bytes
    ) -> Optional[CredentialRecord]:
        """Look up a single credential by RP ID and credential ID."""
        return self._store.get((rp_id, credential_id))

    def get_credentials_by_rp(self, rp_id: str) -> List[CredentialRecord]:
        """Return all credentials whose ``rp_id`` equals *rp_id* exactly."""
        return [
            record
            for (stored_rp_id, _), record in self._store.items()
            if stored_rp_id == rp_id
        ]

    def increment_sign_count(self, rp_id: str, credential_id: bytes) -> int:
        """Increment ``sign_count`` by 1 and return the new value.

        Raises:
            KeyError: If no credential exists for ``(rp_id, credential_id)``.
        """
        key = (rp_id, credential_id)
        try:
            record = self._store[key]
        except KeyError:
            raise KeyError(
                f"No credential found for rp_id={rp_id!r}, "
                f"credential_id={credential_id!r}"
            ) from None
        record.sign_count += 1
        return record.sign_count

    def delete_credential(self, rp_id: str, credential_id: bytes) -> bool:
        """Delete a credential and return whether it existed."""
        key = (rp_id, credential_id)
        if key in self._store:
            del self._store[key]
            return True
        return False

    def get_all_credentials(self) -> List[CredentialRecord]:
        """Return every credential across all RP IDs."""
        return list(self._store.values())


# ---------------------------------------------------------------------------
# Encrypted file-backed implementation
# ---------------------------------------------------------------------------

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import PysskeyError

_PBKDF2_ITERATIONS = 600_000
_KEY_LEN = 32   # 256-bit AES key
_NONCE_LEN = 12  # 96-bit nonce (AES-GCM standard)
_SALT_LEN = 16


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from *passphrase* and *salt* via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase)


def _record_to_dict(record: CredentialRecord) -> dict:
    """Serialize a ``CredentialRecord`` to a JSON-safe dict (bytes → base64)."""
    return {
        "credential_id": base64.b64encode(record.credential_id).decode(),
        "rp_id": record.rp_id,
        "user_id": base64.b64encode(record.user_id).decode(),
        "user_name": record.user_name,
        "user_display_name": record.user_display_name,
        "alg": record.alg,
        "private_key_pem": base64.b64encode(record.private_key_pem).decode(),
        "public_key_cose": base64.b64encode(record.public_key_cose).decode(),
        "sign_count": record.sign_count,
        "discoverable": record.discoverable,
    }


def _dict_to_record(d: dict) -> CredentialRecord:
    """Deserialize a dict (base64 bytes fields) back to a ``CredentialRecord``."""
    return CredentialRecord(
        credential_id=base64.b64decode(d["credential_id"]),
        rp_id=d["rp_id"],
        user_id=base64.b64decode(d["user_id"]),
        user_name=d["user_name"],
        user_display_name=d["user_display_name"],
        alg=d["alg"],
        private_key_pem=base64.b64decode(d["private_key_pem"]),
        public_key_cose=base64.b64decode(d["public_key_cose"]),
        sign_count=d["sign_count"],
        discoverable=d["discoverable"],
    )


class EncryptedFileStore(CredentialStore):
    """AES-256-GCM encrypted, file-backed ``CredentialStore``.

    All credential records are serialised to JSON, encrypted with AES-256-GCM
    using a key derived from *passphrase* via PBKDF2-HMAC-SHA256
    (600 000 iterations), and written to *file_path* as a JSON envelope:

    .. code-block:: json

        {
            "salt": "<16 bytes hex>",
            "nonce": "<12 bytes hex>",
            "ciphertext": "<N bytes hex>"
        }

    A fresh salt is generated on first write; subsequent writes reuse the same
    salt so the key remains stable for the lifetime of the file.  A new random
    nonce is generated for every write (each nonce must only be used once per
    key per AES-GCM).

    Opening an existing file with an incorrect passphrase raises
    :class:`pysskey.exceptions.PysskeyError`.
    """

    def __init__(
        self,
        file_path: "str | Path",
        passphrase: "str | bytes",
    ) -> None:
        self._path = Path(file_path)
        # Normalise passphrase to bytes
        self._passphrase: bytes = (
            passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        )

        # In-memory cache backed by InMemoryStore
        self._cache = InMemoryStore()

        if self._path.exists():
            # Load and decrypt the existing vault; raises PysskeyError on bad key
            self._salt, records = self._load()
            for record in records:
                self._cache.save_credential(record)
        else:
            # New vault: generate a fresh random salt
            self._salt = os.urandom(_SALT_LEN)

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------

    def _encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* and write the envelope to disk.

        Returns the raw ciphertext (nonce prepended by AESGCM or handled
        separately — here we store nonce + tag in the JSON envelope).
        """
        key = _derive_key(self._passphrase, self._salt)
        nonce = os.urandom(_NONCE_LEN)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        envelope = {
            "salt": self._salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }
        self._path.write_text(json.dumps(envelope), encoding="utf-8")
        return ciphertext

    def _load(self) -> "tuple[bytes, list[CredentialRecord]]":
        """Read the envelope from disk, decrypt, and return ``(salt, records)``."""
        try:
            envelope = json.loads(self._path.read_text(encoding="utf-8"))
            salt = bytes.fromhex(envelope["salt"])
            nonce = bytes.fromhex(envelope["nonce"])
            ciphertext = bytes.fromhex(envelope["ciphertext"])

            key = _derive_key(self._passphrase, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise PysskeyError(
                "Decryption failed: incorrect passphrase or corrupted vault."
            ) from exc
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            raise PysskeyError(
                f"Vault file is corrupted or has an unrecognised format: {exc}"
            ) from exc

        records_raw: list[dict] = json.loads(plaintext.decode("utf-8"))
        records = [_dict_to_record(d) for d in records_raw]
        return salt, records

    def _flush(self) -> None:
        """Serialize the entire in-memory cache and write it encrypted to disk."""
        records = list(self._cache._store.values())
        plaintext = json.dumps([_record_to_dict(r) for r in records]).encode("utf-8")
        self._encrypt(plaintext)

    # ------------------------------------------------------------------
    # CredentialStore implementation
    # ------------------------------------------------------------------

    def save_credential(self, record: CredentialRecord) -> None:
        self._cache.save_credential(record)
        self._flush()

    def get_credential(
        self, rp_id: str, credential_id: bytes
    ) -> Optional[CredentialRecord]:
        return self._cache.get_credential(rp_id, credential_id)

    def get_credentials_by_rp(self, rp_id: str) -> List[CredentialRecord]:
        return self._cache.get_credentials_by_rp(rp_id)

    def increment_sign_count(self, rp_id: str, credential_id: bytes) -> int:
        new_count = self._cache.increment_sign_count(rp_id, credential_id)
        self._flush()
        return new_count

    def delete_credential(self, rp_id: str, credential_id: bytes) -> bool:
        deleted = self._cache.delete_credential(rp_id, credential_id)
        if deleted:
            self._flush()
        return deleted

    def get_all_credentials(self) -> List[CredentialRecord]:
        return self._cache.get_all_credentials()
