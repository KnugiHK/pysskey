"""Tests for the interactive demo server's API handlers."""

from __future__ import annotations

import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from pysskey.models import CredentialRecord, b64url_encode
from pysskey.store import InMemoryStore


_SERVER_PATH = Path(__file__).resolve().parents[1] / "demo-server" / "demo_server.py"
_SERVER_SPEC = spec_from_file_location("pysskey_demo_server", _SERVER_PATH)
assert _SERVER_SPEC is not None and _SERVER_SPEC.loader is not None
demo_server = module_from_spec(_SERVER_SPEC)
_SERVER_SPEC.loader.exec_module(demo_server)


def make_record(credential_id: bytes, rp_id: str) -> CredentialRecord:
    return CredentialRecord(
        credential_id=credential_id,
        rp_id=rp_id,
        user_id=b"\xaa" * 8,
        user_name="alice@example.com",
        user_display_name="Alice",
        alg=-7,
        private_key_pem=b"FAKE_PEM",
        public_key_cose=b"\xa0",
    )


def test_status_without_rp_id_returns_all_credentials(monkeypatch):
    store = InMemoryStore()
    store.save_credential(make_record(b"\x01" * 16, "example.com"))
    store.save_credential(make_record(b"\x02" * 16, "other.com"))
    monkeypatch.setattr(demo_server, "_store", store)

    response = demo_server.api_status({})

    assert response["ok"] is True
    assert response["data"]["count"] == 2
    assert response["data"]["rpId"] is None
    assert {credential["rpId"] for credential in response["data"]["credentials"]} == {
        "example.com",
        "other.com",
    }
    assert "private_key_pem" not in response["data"]["credentials"][0]


def test_status_with_rp_id_remains_filtered(monkeypatch):
    store = InMemoryStore()
    store.save_credential(make_record(b"\x01" * 16, "example.com"))
    store.save_credential(make_record(b"\x02" * 16, "other.com"))
    monkeypatch.setattr(demo_server, "_store", store)

    response = demo_server.api_status({"rpId": "example.com"})

    assert response["ok"] is True
    assert response["data"]["count"] == 1
    assert response["data"]["rpId"] == "example.com"
    assert response["data"]["credentials"][0]["rpId"] == "example.com"


def test_status_without_rp_id_returns_empty_credentials_for_empty_store(monkeypatch):
    monkeypatch.setattr(demo_server, "_store", InMemoryStore())

    response = demo_server.api_status({})

    assert response["ok"] is True
    assert response["data"]["count"] == 0
    assert response["data"]["credentials"] == []


def test_credential_secret_returns_key_only_when_explicitly_requested(monkeypatch):
    store = InMemoryStore()
    record = make_record(b"\x01" * 16, "example.com")
    store.save_credential(record)
    monkeypatch.setattr(demo_server, "_store", store)

    status_response = demo_server.api_status({})
    secret_response = demo_server.api_credential_secret({
        "rpId": record.rp_id,
        "credentialId": b64url_encode(record.credential_id),
    })

    assert "privateKeyPem" not in status_response["data"]["credentials"][0]
    assert secret_response == {
        "ok": True,
        "data": {"privateKeyPem": "FAKE_PEM"},
    }


def test_credential_secret_requires_an_existing_matching_credential(monkeypatch):
    store = InMemoryStore()
    record = make_record(b"\x01" * 16, "example.com")
    store.save_credential(record)
    monkeypatch.setattr(demo_server, "_store", store)

    response = demo_server.api_credential_secret({
        "rpId": record.rp_id,
        "credentialId": b64url_encode(b"\xff" * 16),
    })

    assert response == {"ok": False, "error": "Credential not found."}


def test_credential_secret_rejects_missing_fields():
    assert demo_server.api_credential_secret({}) == {
        "ok": False,
        "error": "rpId is required.",
    }


def test_credential_secret_rejects_non_base64url_ids():
    assert demo_server.api_credential_secret({
        "rpId": "example.com",
        "credentialId": "not/base64url",
    }) == {
        "ok": False,
        "error": "credentialId must be a valid base64url value.",
    }


def test_secret_http_endpoint_is_same_origin_and_not_cached(monkeypatch):
    store = InMemoryStore()
    record = make_record(b"\x01" * 16, "example.com")
    store.save_credential(record)
    monkeypatch.setattr(demo_server, "_store", store)

    server = demo_server.HTTPServer(("127.0.0.1", 0), demo_server._Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    payload = json.dumps({
        "rpId": record.rp_id,
        "credentialId": b64url_encode(record.credential_id),
    }).encode()

    try:
        foreign_request = Request(
            f"{base_url}/api/credential-secret",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Origin": "https://attacker.example",
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as error:
            urlopen(foreign_request)
        assert error.value.code == 403
        assert error.value.headers.get("Access-Control-Allow-Origin") is None

        local_request = Request(
            f"{base_url}/api/credential-secret",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Origin": base_url,
            },
            method="POST",
        )
        with urlopen(local_request) as response:
            result = json.load(response)
            assert response.headers["Cache-Control"] == "no-store"
        assert result["data"]["privateKeyPem"] == "FAKE_PEM"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
