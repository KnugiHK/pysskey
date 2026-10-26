"""Unit tests for CredentialStore ABC and InMemoryStore (task 4.1)."""

from __future__ import annotations

import pytest

from pysskey.models import CredentialRecord
from pysskey.store import CredentialStore, InMemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_record(
    credential_id: bytes = b"\x01" * 16,
    rp_id: str = "example.com",
    sign_count: int = 0,
) -> CredentialRecord:
    return CredentialRecord(
        credential_id=credential_id,
        rp_id=rp_id,
        user_id=b"\xaa" * 8,
        user_name="alice@example.com",
        user_display_name="Alice",
        alg=-7,
        private_key_pem=b"FAKE_PEM",
        public_key_cose=b"\xa0",  # empty CBOR map placeholder
        sign_count=sign_count,
    )


# ---------------------------------------------------------------------------
# ABC contract
# ---------------------------------------------------------------------------

class TestCredentialStoreABC:
    def test_cannot_instantiate_abstract_class(self):
        with pytest.raises(TypeError):
            CredentialStore()  # type: ignore[abstract]

    def test_in_memory_store_is_subclass(self):
        assert issubclass(InMemoryStore, CredentialStore)


# ---------------------------------------------------------------------------
# save_credential / get_credential
# ---------------------------------------------------------------------------

class TestSaveAndGet:
    def test_save_then_get_returns_same_record(self):
        store = InMemoryStore()
        record = make_record()
        store.save_credential(record)
        result = store.get_credential(record.rp_id, record.credential_id)
        assert result is record

    def test_get_nonexistent_returns_none(self):
        store = InMemoryStore()
        result = store.get_credential("missing.example.com", b"\xff" * 16)
        assert result is None

    def test_save_overwrites_existing_entry(self):
        store = InMemoryStore()
        record_v1 = make_record(sign_count=0)
        record_v2 = make_record(sign_count=5)
        store.save_credential(record_v1)
        store.save_credential(record_v2)
        result = store.get_credential(record_v1.rp_id, record_v1.credential_id)
        assert result.sign_count == 5

    def test_different_rp_ids_are_isolated(self):
        store = InMemoryStore()
        # Use distinct credential IDs so the lookup key differs for each record
        r1 = make_record(credential_id=b"\x01" * 16, rp_id="alpha.com")
        r2 = make_record(credential_id=b"\x02" * 16, rp_id="beta.com")
        store.save_credential(r1)
        store.save_credential(r2)
        assert store.get_credential("alpha.com", r1.credential_id) is r1
        assert store.get_credential("beta.com", r2.credential_id) is r2
        # r2's credential_id should not be found under alpha.com
        assert store.get_credential("alpha.com", r2.credential_id) is None

    def test_different_credential_ids_under_same_rp(self):
        store = InMemoryStore()
        r1 = make_record(credential_id=b"\x01" * 16)
        r2 = make_record(credential_id=b"\x02" * 16)
        store.save_credential(r1)
        store.save_credential(r2)
        assert store.get_credential("example.com", b"\x01" * 16) is r1
        assert store.get_credential("example.com", b"\x02" * 16) is r2


# ---------------------------------------------------------------------------
# get_credentials_by_rp
# ---------------------------------------------------------------------------

class TestGetCredentialsByRp:
    def test_returns_all_matching_rp_credentials(self):
        store = InMemoryStore()
        r1 = make_record(credential_id=b"\x01" * 16, rp_id="example.com")
        r2 = make_record(credential_id=b"\x02" * 16, rp_id="example.com")
        r3 = make_record(credential_id=b"\x03" * 16, rp_id="other.com")
        store.save_credential(r1)
        store.save_credential(r2)
        store.save_credential(r3)
        results = store.get_credentials_by_rp("example.com")
        assert len(results) == 2
        assert r1 in results
        assert r2 in results

    def test_returns_empty_list_for_unknown_rp(self):
        store = InMemoryStore()
        assert store.get_credentials_by_rp("nobody.com") == []

    def test_exact_rp_id_match_only(self):
        """'example.com' must NOT return credentials for 'sub.example.com'."""
        store = InMemoryStore()
        r1 = make_record(rp_id="example.com")
        r2 = make_record(credential_id=b"\x02" * 16, rp_id="sub.example.com")
        store.save_credential(r1)
        store.save_credential(r2)
        assert store.get_credentials_by_rp("example.com") == [r1]
        assert store.get_credentials_by_rp("sub.example.com") == [r2]


# ---------------------------------------------------------------------------
# get_all_credentials
# ---------------------------------------------------------------------------

class TestGetAllCredentials:
    def test_returns_credentials_across_all_rp_ids(self):
        store = InMemoryStore()
        r1 = make_record(credential_id=b"\x01" * 16, rp_id="example.com")
        r2 = make_record(credential_id=b"\x02" * 16, rp_id="other.com")
        store.save_credential(r1)
        store.save_credential(r2)

        assert store.get_all_credentials() == [r1, r2]

    def test_returns_empty_list_when_store_is_empty(self):
        assert InMemoryStore().get_all_credentials() == []


# ---------------------------------------------------------------------------
# increment_sign_count
# ---------------------------------------------------------------------------

class TestIncrementSignCount:
    def test_increments_from_zero(self):
        store = InMemoryStore()
        record = make_record(sign_count=0)
        store.save_credential(record)
        new_count = store.increment_sign_count(record.rp_id, record.credential_id)
        assert new_count == 1

    def test_increment_updates_stored_record(self):
        store = InMemoryStore()
        record = make_record(sign_count=0)
        store.save_credential(record)
        store.increment_sign_count(record.rp_id, record.credential_id)
        assert store.get_credential(record.rp_id, record.credential_id).sign_count == 1

    def test_successive_increments_are_monotonic(self):
        store = InMemoryStore()
        record = make_record(sign_count=10)
        store.save_credential(record)
        for expected in range(11, 16):
            count = store.increment_sign_count(record.rp_id, record.credential_id)
            assert count == expected

    def test_increment_nonexistent_raises_key_error(self):
        store = InMemoryStore()
        with pytest.raises(KeyError):
            store.increment_sign_count("missing.com", b"\x00" * 16)


# ---------------------------------------------------------------------------
# delete_credential
# ---------------------------------------------------------------------------

class TestDeleteCredential:
    def test_delete_existing_returns_true(self):
        store = InMemoryStore()
        record = make_record()
        store.save_credential(record)
        assert store.delete_credential(record.rp_id, record.credential_id) is True

    def test_delete_removes_record(self):
        store = InMemoryStore()
        record = make_record()
        store.save_credential(record)
        store.delete_credential(record.rp_id, record.credential_id)
        assert store.get_credential(record.rp_id, record.credential_id) is None

    def test_delete_nonexistent_returns_false(self):
        store = InMemoryStore()
        assert store.delete_credential("missing.com", b"\x00" * 16) is False

    def test_delete_only_removes_targeted_credential(self):
        store = InMemoryStore()
        r1 = make_record(credential_id=b"\x01" * 16)
        r2 = make_record(credential_id=b"\x02" * 16)
        store.save_credential(r1)
        store.save_credential(r2)
        store.delete_credential(r1.rp_id, r1.credential_id)
        assert store.get_credential(r2.rp_id, r2.credential_id) is r2


# ---------------------------------------------------------------------------
# EncryptedFileStore
# ---------------------------------------------------------------------------

from pysskey.store import EncryptedFileStore
from pysskey.exceptions import PysskeyError


class TestEncryptedFileStore:
    """Tests for the AES-256-GCM encrypted, file-backed CredentialStore."""

    PASSPHRASE = "correct-horse-battery-staple"

    def _store(self, tmp_path, passphrase=None):
        """Helper: return a fresh EncryptedFileStore backed by a temp file."""
        return EncryptedFileStore(
            tmp_path / "vault.json",
            passphrase if passphrase is not None else self.PASSPHRASE,
        )

    # ------------------------------------------------------------------
    # save / get
    # ------------------------------------------------------------------

    def test_save_then_get(self, tmp_path):
        store = self._store(tmp_path)
        record = make_record()
        store.save_credential(record)
        result = store.get_credential(record.rp_id, record.credential_id)
        assert result is not None
        assert result.credential_id == record.credential_id
        assert result.rp_id == record.rp_id

    def test_get_nonexistent_returns_none(self, tmp_path):
        store = self._store(tmp_path)
        assert store.get_credential("missing.com", b"\xff" * 16) is None

    def test_save_overwrites_existing(self, tmp_path):
        store = self._store(tmp_path)
        r1 = make_record(sign_count=0)
        r2 = make_record(sign_count=99)
        store.save_credential(r1)
        store.save_credential(r2)
        result = store.get_credential(r1.rp_id, r1.credential_id)
        assert result.sign_count == 99

    # ------------------------------------------------------------------
    # get_credentials_by_rp
    # ------------------------------------------------------------------

    def test_get_credentials_by_rp(self, tmp_path):
        store = self._store(tmp_path)
        r1 = make_record(credential_id=b"\x01" * 16, rp_id="example.com")
        r2 = make_record(credential_id=b"\x02" * 16, rp_id="example.com")
        r3 = make_record(credential_id=b"\x03" * 16, rp_id="other.com")
        store.save_credential(r1)
        store.save_credential(r2)
        store.save_credential(r3)
        results = store.get_credentials_by_rp("example.com")
        assert len(results) == 2
        ids = {r.credential_id for r in results}
        assert b"\x01" * 16 in ids
        assert b"\x02" * 16 in ids

    def test_get_credentials_by_rp_empty(self, tmp_path):
        store = self._store(tmp_path)
        assert store.get_credentials_by_rp("nobody.com") == []

    def test_get_all_credentials_across_rp_ids(self, tmp_path):
        vault = tmp_path / "vault.json"
        r1 = make_record(credential_id=b"\x01" * 16, rp_id="example.com")
        r2 = make_record(credential_id=b"\x02" * 16, rp_id="other.com")

        store = EncryptedFileStore(vault, self.PASSPHRASE)
        store.save_credential(r1)
        store.save_credential(r2)

        reloaded_store = EncryptedFileStore(vault, self.PASSPHRASE)
        assert {record.rp_id for record in reloaded_store.get_all_credentials()} == {
            "example.com",
            "other.com",
        }

    # ------------------------------------------------------------------
    # increment_sign_count
    # ------------------------------------------------------------------

    def test_increment_sign_count(self, tmp_path):
        store = self._store(tmp_path)
        record = make_record(sign_count=0)
        store.save_credential(record)
        new_count = store.increment_sign_count(record.rp_id, record.credential_id)
        assert new_count == 1

    def test_increment_sign_count_persists(self, tmp_path):
        vault = tmp_path / "vault.json"
        # First instance: save and increment
        store1 = EncryptedFileStore(vault, self.PASSPHRASE)
        record = make_record(sign_count=0)
        store1.save_credential(record)
        store1.increment_sign_count(record.rp_id, record.credential_id)

        # Second instance: reload from disk
        store2 = EncryptedFileStore(vault, self.PASSPHRASE)
        result = store2.get_credential(record.rp_id, record.credential_id)
        assert result is not None
        assert result.sign_count == 1

    def test_increment_nonexistent_raises(self, tmp_path):
        store = self._store(tmp_path)
        with pytest.raises(KeyError):
            store.increment_sign_count("missing.com", b"\x00" * 16)

    # ------------------------------------------------------------------
    # delete_credential
    # ------------------------------------------------------------------

    def test_delete_existing(self, tmp_path):
        store = self._store(tmp_path)
        record = make_record()
        store.save_credential(record)
        assert store.delete_credential(record.rp_id, record.credential_id) is True
        assert store.get_credential(record.rp_id, record.credential_id) is None

    def test_delete_nonexistent(self, tmp_path):
        store = self._store(tmp_path)
        assert store.delete_credential("missing.com", b"\x00" * 16) is False

    # ------------------------------------------------------------------
    # Persistence across instances
    # ------------------------------------------------------------------

    def test_persistence_across_instances(self, tmp_path):
        vault = tmp_path / "vault.json"
        r1 = make_record(credential_id=b"\x01" * 16, rp_id="example.com")
        r2 = make_record(credential_id=b"\x02" * 16, rp_id="example.com")

        # Write with first instance
        store1 = EncryptedFileStore(vault, self.PASSPHRASE)
        store1.save_credential(r1)
        store1.save_credential(r2)

        # Read with a brand-new instance
        store2 = EncryptedFileStore(vault, self.PASSPHRASE)
        results = store2.get_credentials_by_rp("example.com")
        assert len(results) == 2
        ids = {r.credential_id for r in results}
        assert b"\x01" * 16 in ids
        assert b"\x02" * 16 in ids

    # ------------------------------------------------------------------
    # Wrong passphrase
    # ------------------------------------------------------------------

    def test_wrong_passphrase_raises(self, tmp_path):
        vault = tmp_path / "vault.json"
        # Create and write a vault with the correct passphrase
        store = EncryptedFileStore(vault, self.PASSPHRASE)
        store.save_credential(make_record())

        # Attempting to open the same file with a wrong passphrase must raise PysskeyError
        with pytest.raises(PysskeyError):
            EncryptedFileStore(vault, "wrong-passphrase")

    def test_corrupt_envelope_missing_key_raises(self, tmp_path):
        """A vault file with valid JSON but missing envelope keys raises PysskeyError."""
        vault = tmp_path / "vault.json"
        # Write a JSON file that is valid JSON but lacks the required envelope keys
        vault.write_text('{"unexpected": "structure"}', encoding="utf-8")
        with pytest.raises(PysskeyError):
            EncryptedFileStore(vault, self.PASSPHRASE)
