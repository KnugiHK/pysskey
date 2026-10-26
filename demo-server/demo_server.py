"""
Lightweight HTTP server for the pysskey interactive testing front-end.

Serves frontend.html and a JSON API that exercises PasskeyProvider, stores,
crypto, and authenticator data — all the same surface covered by test_harness.py,
but interactively through a browser.

Usage:
    python demo-server/demo_server.py          # listens on http://localhost:8742
    python demo-server/demo_server.py --port 9000
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ── Ensure the package root is importable when running from any cwd ───────────
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import cbor2

from pysskey.authenticator_data import (
    FLAG_AT,
    FLAG_BE,
    FLAG_BS,
    FLAG_UP,
    FLAG_UV,
    build_client_data_json,
    pack_attested_credential_data,
    pack_authenticator_data,
    parse_authenticator_data,
)
from pysskey.crypto import generate_keypair, sign_payload, verify_signature
from pysskey.exceptions import (
    CredentialExcludedError,
    NoCredentialsFoundError,
    OriginMismatchError,
    PysskeyError,
    UnsupportedAlgorithmError,
    UserVerificationError,
)
from pysskey.models import (
    b64url_decode,
    b64url_encode,
)
from pysskey.provider import PasskeyProvider, validate_origin
from pysskey.store import InMemoryStore

# ── Session state (one provider + store per server process) ───────────────────
_store = InMemoryStore()
_provider = PasskeyProvider(
    store=_store,
    up_callback=lambda rp, act: True,
    uv_callback=lambda rp: True,
)
_last_registration: dict[str, Any] = {}   # raw_id  -> reg response dict
_last_challenge: bytes = b""

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ok(data: Any) -> dict:
    return {"ok": True, "data": data}


def _err(msg: str) -> dict:
    return {"ok": False, "error": msg}


def _bytes_to_hex(b: bytes) -> str:
    return b.hex()


def _parse_body(handler: "BaseHTTPRequestHandler") -> dict:
    length = int(handler.headers.get("Content-Length", 0))
    raw = handler.rfile.read(length)
    return json.loads(raw) if raw else {}


# ═══════════════════════════════════════════════════════════════════════════════
# API Route handlers
# ═══════════════════════════════════════════════════════════════════════════════

def api_reset(body: dict) -> dict:
    """Reset the in-memory store and provider back to empty state."""
    global _store, _provider, _last_registration, _last_challenge
    _store = InMemoryStore()
    _provider = PasskeyProvider(
        store=_store,
        up_callback=lambda rp, act: True,
        uv_callback=lambda rp: True,
    )
    _last_registration = {}
    _last_challenge = b""
    return _ok({"message": "Store and provider reset."})


def api_status(body: dict) -> dict:
    """Return current store contents (without private key material).

    If ``rpId`` is omitted or empty, returns every credential across all RP IDs.
    """
    rp_id = body.get("rpId", "").strip()
    if rp_id:
        creds = _store.get_credentials_by_rp(rp_id)
    else:
        creds = _store.get_all_credentials()
    result = []
    for c in creds:
        result.append({
            "credentialId": b64url_encode(c.credential_id),
            "rpId": c.rp_id,
            "userName": c.user_name,
            "userDisplayName": c.user_display_name,
            "alg": c.alg,
            "signCount": c.sign_count,
            "discoverable": c.discoverable,
        })
    return _ok({"credentials": result, "count": len(result), "rpId": rp_id or None})


def api_credential_secret(body: dict) -> dict:
    """Return one credential's private key after an explicit inspector request."""
    rp_id = body.get("rpId")
    encoded_credential_id = body.get("credentialId")
    if not isinstance(rp_id, str) or not rp_id.strip():
        return _err("rpId is required.")
    rp_id = rp_id.strip()
    if not isinstance(encoded_credential_id, str) or not encoded_credential_id:
        return _err("credentialId is required.")
    if any(
        not (char.isascii() and (char.isalnum() or char in "-_"))
        for char in encoded_credential_id
    ):
        return _err("credentialId must be a valid base64url value.")
    try:
        credential_id = b64url_decode(encoded_credential_id)
    except (ValueError, binascii.Error):
        return _err("credentialId must be a valid base64url value.")

    credential = _store.get_credential(rp_id, credential_id)
    if credential is None:
        return _err("Credential not found.")
    return _ok({"privateKeyPem": credential.private_key_pem.decode("utf-8")})


# ── Crypto ────────────────────────────────────────────────────────────────────

def api_generate_keypair(body: dict) -> dict:
    """Generate a keypair for the specified COSE algorithm."""
    alg = int(body.get("alg", -7))
    priv_pem, pub_cose = generate_keypair(alg)
    cose_map = cbor2.loads(pub_cose)
    return _ok({
        "alg": alg,
        "algName": "ES256" if alg == -7 else "EdDSA",
        "privateKeyPemPreview": priv_pem.decode()[:64] + "…",
        "publicKeyCoseHex": _bytes_to_hex(pub_cose),
        "coseKeyType": cose_map.get(1),
        "coseAlg": cose_map.get(3),
    })


def api_sign_and_verify(body: dict) -> dict:
    """Generate a keypair, sign a message, verify it, then verify a tampered version."""
    alg = int(body.get("alg", -7))
    message = body.get("message", "Hello, pysskey!").encode()
    priv_pem, pub_cose = generate_keypair(alg)
    signature = sign_payload(priv_pem, alg, message)
    valid = verify_signature(pub_cose, alg, message, signature)
    tampered = verify_signature(pub_cose, alg, b"TAMPERED_" + message, signature)
    return _ok({
        "alg": alg,
        "algName": "ES256" if alg == -7 else "EdDSA",
        "message": message.decode(errors="replace"),
        "signatureHex": _bytes_to_hex(signature),
        "signatureBytes": len(signature),
        "verifyOriginal": valid,
        "verifyTampered": tampered,
    })


# ── Authenticator Data ────────────────────────────────────────────────────────

def api_build_client_data_json(body: dict) -> dict:
    """Build a clientDataJSON blob."""
    wtype = body.get("type", "webauthn.create")
    challenge = os.urandom(32)
    origin = body.get("origin", "https://example.com")
    raw = build_client_data_json(wtype, challenge, origin)
    parsed = json.loads(raw.decode())
    return _ok({
        "raw": raw.decode(),
        "parsed": parsed,
        "challengeHex": _bytes_to_hex(challenge),
    })


def api_pack_parse_auth_data(body: dict) -> dict:
    """Pack then parse authenticatorData with attested credential data."""
    alg = int(body.get("alg", -7))
    rp_id = body.get("rpId", "example.com")
    sign_count = int(body.get("signCount", 42))

    aaguid = bytes.fromhex(body.get("aaguid", "aa" * 16))
    cred_id = os.urandom(16)
    _, pub_cose = generate_keypair(alg)

    att_data = pack_attested_credential_data(aaguid, cred_id, pub_cose)
    flags = FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE | FLAG_BS
    auth_data = pack_authenticator_data(rp_id, flags, sign_count, att_data)
    parsed = parse_authenticator_data(auth_data)

    return _ok({
        "authDataHex": _bytes_to_hex(auth_data),
        "authDataBytes": len(auth_data),
        "parsed": {
            "rpIdHash": _bytes_to_hex(parsed["rp_id_hash"]),
            "rpIdHashMatches": parsed["rp_id_hash"] == hashlib.sha256(rp_id.encode()).digest(),
            "flags": parsed["flags"],
            "flagsDecoded": {
                "UP": bool(parsed["flags"] & FLAG_UP),
                "UV": bool(parsed["flags"] & FLAG_UV),
                "BE": bool(parsed["flags"] & FLAG_BE),
                "BS": bool(parsed["flags"] & FLAG_BS),
                "AT": bool(parsed["flags"] & FLAG_AT),
            },
            "signCount": parsed["sign_count"],
            "aaguid": _bytes_to_hex(parsed["aaguid"]),
            "credentialId": _bytes_to_hex(parsed["credential_id"]),
            "hasAttestedCredData": parsed["has_attested_cred_data"],
        },
    })


# ── Origin Validation ─────────────────────────────────────────────────────────

def api_validate_origin(body: dict) -> dict:
    """Run validate_origin for a batch of test cases."""
    cases = body.get("cases", [
        {"origin": "https://example.com",       "rpId": "example.com",  "expect": True},
        {"origin": "https://login.example.com", "rpId": "example.com",  "expect": True},
        {"origin": "http://localhost:8000",      "rpId": "localhost",    "expect": True},
        {"origin": "http://example.com",         "rpId": "example.com",  "expect": False},
        {"origin": "https://evil-example.com",   "rpId": "example.com",  "expect": False},
        {"origin": "ftp://example.com",          "rpId": "example.com",  "expect": False},
    ])
    results = []
    for c in cases:
        result = validate_origin(c["origin"], c["rpId"])
        expected = c.get("expect")
        results.append({
            "origin": c["origin"],
            "rpId": c["rpId"],
            "result": result,
            "expected": expected,
            "pass": result == expected if expected is not None else None,
        })
    all_passed = all(r["pass"] for r in results if r["pass"] is not None)
    return _ok({"results": results, "allPassed": all_passed})


# ── Provider: Registration ─────────────────────────────────────────────────────

def api_register(body: dict) -> dict:
    """Call PasskeyProvider.create() and return a structured summary."""
    global _last_challenge
    rp_id = body.get("rpId", "example.com")
    origin = body.get("origin", f"https://{rp_id}")
    user_name = body.get("userName", "alice@example.com")
    user_display = body.get("userDisplayName", "Alice")
    alg = int(body.get("alg", -7))
    attestation = body.get("attestation", "none")
    uv = body.get("userVerification", "required")
    up_allow = body.get("upAllow", True)
    uv_allow = body.get("uvAllow", True)

    _last_challenge = os.urandom(32)

    options = {
        "rp": {"id": rp_id, "name": rp_id},
        "user": {
            "id": os.urandom(16),
            "name": user_name,
            "displayName": user_display,
        },
        "challenge": _last_challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": alg}],
        "excludeCredentials": [],
        "authenticatorSelection": {
            "residentKey": "required",
            "userVerification": uv,
        },
        "attestation": attestation,
    }

    # Swap provider callbacks as requested
    local_provider = PasskeyProvider(
        store=_store,
        up_callback=lambda r, a: up_allow,
        uv_callback=lambda r: uv_allow,
    )

    reg = local_provider.create(options, origin)

    # Parse the attestation object for display
    att_obj = cbor2.loads(reg.attestation_object)
    parsed_auth = parse_authenticator_data(att_obj["authData"])
    _last_registration[b64url_encode(reg.raw_id)] = reg

    return _ok({
        "id": reg.id,
        "rawIdHex": _bytes_to_hex(reg.raw_id),
        "transports": reg.transports,
        "attestationFmt": att_obj.get("fmt", "none"),
        "attestationObject": {
            "fmt": att_obj["fmt"],
            "hasAttStmt": bool(att_obj.get("attStmt")),
            "attStmtKeys": list(att_obj.get("attStmt", {}).keys()),
        },
        "authData": {
            "rpIdHashHex": _bytes_to_hex(parsed_auth["rp_id_hash"]),
            "rpIdHashMatches": parsed_auth["rp_id_hash"] == hashlib.sha256(rp_id.encode()).digest(),
            "flags": parsed_auth["flags"],
            "flagsDecoded": {
                "UP": bool(parsed_auth["flags"] & FLAG_UP),
                "UV": bool(parsed_auth["flags"] & FLAG_UV),
                "AT": bool(parsed_auth["flags"] & FLAG_AT),
                "BE": bool(parsed_auth["flags"] & FLAG_BE),
                "BS": bool(parsed_auth["flags"] & FLAG_BS),
            },
            "signCount": parsed_auth["sign_count"],
            "aaguid": _bytes_to_hex(parsed_auth["aaguid"]) if parsed_auth["aaguid"] else None,
            "credentialId": _bytes_to_hex(parsed_auth["credential_id"]) if parsed_auth["credential_id"] else None,
        },
    })


def api_register_duplicate(body: dict) -> dict:
    """Attempt duplicate registration — should raise CredentialExcludedError."""
    rp_id = body.get("rpId", "example.com")
    origin = body.get("origin", f"https://{rp_id}")

    creds = _store.get_credentials_by_rp(rp_id)
    if not creds:
        return _err(f"No credentials registered for {rp_id!r} yet — register first.")

    exclude = [{"type": "public-key", "id": c.credential_id} for c in creds]
    options = {
        "rp": {"id": rp_id, "name": rp_id},
        "user": {"id": os.urandom(16), "name": "dup@example.com", "displayName": "Dup"},
        "challenge": os.urandom(32),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "excludeCredentials": exclude,
    }
    try:
        _provider.create(options, origin)
        return _err("Expected CredentialExcludedError but create() succeeded — this is a BUG.")
    except CredentialExcludedError as exc:
        return _ok({"caught": "CredentialExcludedError", "message": str(exc)})


# ── Provider: Authentication ───────────────────────────────────────────────────

def api_authenticate(body: dict) -> dict:
    """Call PasskeyProvider.get() and cryptographically verify the result."""
    rp_id = body.get("rpId", "example.com")
    origin = body.get("origin", f"https://{rp_id}")
    uv = body.get("userVerification", "required")
    allow_creds = body.get("allowCredentials", [])
    up_allow = body.get("upAllow", True)
    uv_allow = body.get("uvAllow", True)

    options: dict[str, Any] = {
        "rpId": rp_id,
        "challenge": os.urandom(32),
        "allowCredentials": allow_creds,
        "userVerification": uv,
    }

    local_provider = PasskeyProvider(
        store=_store,
        up_callback=lambda r, a: up_allow,
        uv_callback=lambda r: uv_allow,
    )
    auth = local_provider.get(options, origin)

    # Server-side verification (as an RP would do)
    stored_cred = _store.get_credential(rp_id, auth.raw_id)
    client_data_hash = hashlib.sha256(auth.client_data_json).digest()
    signed_data = auth.authenticator_data + client_data_hash
    sig_valid = verify_signature(
        stored_cred.public_key_cose,
        stored_cred.alg,
        signed_data,
        auth.signature,
    )

    parsed_auth = parse_authenticator_data(auth.authenticator_data)

    return _ok({
        "id": auth.id,
        "rawIdHex": _bytes_to_hex(auth.raw_id),
        "userHandle": b64url_encode(auth.user_handle) if auth.user_handle else None,
        "signatureHex": _bytes_to_hex(auth.signature),
        "signatureBytes": len(auth.signature),
        "serverSideVerification": {
            "signatureValid": sig_valid,
            "signCount": stored_cred.sign_count,
        },
        "authData": {
            "flags": parsed_auth["flags"],
            "flagsDecoded": {
                "UP": bool(parsed_auth["flags"] & FLAG_UP),
                "UV": bool(parsed_auth["flags"] & FLAG_UV),
                "AT": bool(parsed_auth["flags"] & FLAG_AT),
            },
            "signCount": parsed_auth["sign_count"],
        },
    })


# ── Provider: Error Cases ─────────────────────────────────────────────────────

def api_error_case(body: dict) -> dict:
    """Trigger a specific error condition and confirm the right exception fires."""
    case = body.get("case", "origin_mismatch")

    if case == "origin_mismatch":
        try:
            opts = {
                "rp": {"id": "example.com", "name": "Ex"},
                "user": {"id": b"1", "name": "u", "displayName": "U"},
                "challenge": b"c",
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            }
            _provider.create(opts, origin="https://evil.com")
            return _err("No exception was raised — BUG.")
        except OriginMismatchError as e:
            return _ok({"caught": "OriginMismatchError", "message": str(e)})

    elif case == "unsupported_alg":
        try:
            generate_keypair(-257)
            return _err("No exception — BUG.")
        except UnsupportedAlgorithmError as e:
            return _ok({"caught": "UnsupportedAlgorithmError", "message": str(e)})

    elif case == "up_denied":
        p = PasskeyProvider(store=InMemoryStore(), up_callback=lambda r, a: False)
        try:
            p.create({
                "rp": {"id": "example.com", "name": "Ex"},
                "user": {"id": b"u", "name": "u", "displayName": "U"},
                "challenge": b"c",
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            }, origin="https://example.com")
            return _err("No exception — BUG.")
        except UserVerificationError as e:
            return _ok({"caught": "UserVerificationError", "message": str(e)})

    elif case == "uv_denied":
        p = PasskeyProvider(
            store=InMemoryStore(),
            up_callback=lambda r, a: True,
            uv_callback=lambda r: False,
        )
        try:
            p.create({
                "rp": {"id": "example.com", "name": "Ex"},
                "user": {"id": b"u", "name": "u", "displayName": "U"},
                "challenge": b"c",
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "authenticatorSelection": {"userVerification": "required"},
            }, origin="https://example.com")
            return _err("No exception — BUG.")
        except UserVerificationError as e:
            return _ok({"caught": "UserVerificationError", "message": str(e)})

    elif case == "no_credentials":
        p = PasskeyProvider(store=InMemoryStore(), up_callback=lambda r, a: True)
        try:
            p.get({"rpId": "empty.com", "challenge": b"c"}, origin="https://empty.com")
            return _err("No exception — BUG.")
        except NoCredentialsFoundError as e:
            return _ok({"caught": "NoCredentialsFoundError", "message": str(e)})

    elif case == "unsupported_alg_provider":
        p = PasskeyProvider(store=InMemoryStore(), up_callback=lambda r, a: True)
        try:
            p.create({
                "rp": {"id": "example.com", "name": "Ex"},
                "user": {"id": b"u", "name": "u", "displayName": "U"},
                "challenge": b"c",
                "pubKeyCredParams": [{"type": "public-key", "alg": -257}],
            }, origin="https://example.com")
            return _err("No exception — BUG.")
        except UnsupportedAlgorithmError as e:
            return _ok({"caught": "UnsupportedAlgorithmError", "message": str(e)})

    return _err(f"Unknown error case: {case!r}")


# ── Full Flow ──────────────────────────────────────────────────────────────────

def api_full_flow(body: dict) -> dict:
    """Run a complete register → authenticate → verify cycle in one call."""
    rp_id = body.get("rpId", "example.com")
    origin = body.get("origin", f"https://{rp_id}")
    alg = int(body.get("alg", -7))
    uv = body.get("userVerification", "required")
    user_name = body.get("userName", "demo@example.com")

    local_store = InMemoryStore()
    local_provider = PasskeyProvider(
        store=local_store,
        up_callback=lambda r, a: True,
        uv_callback=lambda r: True,
    )

    # 1. Register
    create_challenge = os.urandom(32)
    reg = local_provider.create({
        "rp": {"id": rp_id, "name": rp_id},
        "user": {"id": os.urandom(16), "name": user_name, "displayName": user_name},
        "challenge": create_challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": alg}],
        "authenticatorSelection": {"userVerification": uv},
    }, origin)

    # 2. Authenticate
    auth_challenge = os.urandom(32)
    auth = local_provider.get({
        "rpId": rp_id,
        "challenge": auth_challenge,
        "allowCredentials": [],
        "userVerification": uv,
    }, origin)

    # 3. Verify
    stored = local_store.get_credential(rp_id, auth.raw_id)
    client_data_hash = hashlib.sha256(auth.client_data_json).digest()
    signed_data = auth.authenticator_data + client_data_hash
    sig_valid = verify_signature(stored.public_key_cose, stored.alg, signed_data, auth.signature)

    att_obj = cbor2.loads(reg.attestation_object)
    parsed_auth_reg = parse_authenticator_data(att_obj["authData"])
    parsed_auth_auth = parse_authenticator_data(auth.authenticator_data)

    return _ok({
        "rpId": rp_id,
        "origin": origin,
        "alg": alg,
        "algName": "ES256" if alg == -7 else "EdDSA",
        "registration": {
            "credentialId": reg.id,
            "flagsDecoded": {
                "UP": bool(parsed_auth_reg["flags"] & FLAG_UP),
                "UV": bool(parsed_auth_reg["flags"] & FLAG_UV),
                "AT": bool(parsed_auth_reg["flags"] & FLAG_AT),
            },
            "signCount": parsed_auth_reg["sign_count"],
            "attestationFmt": att_obj.get("fmt"),
        },
        "authentication": {
            "credentialId": auth.id,
            "userHandle": b64url_encode(auth.user_handle) if auth.user_handle else None,
            "signCount": stored.sign_count,
            "flagsDecoded": {
                "UP": bool(parsed_auth_auth["flags"] & FLAG_UP),
                "UV": bool(parsed_auth_auth["flags"] & FLAG_UV),
                "AT": bool(parsed_auth_auth["flags"] & FLAG_AT),
            },
        },
        "verification": {
            "signatureValid": sig_valid,
        },
        "allChecksPass": sig_valid
            and bool(parsed_auth_reg["flags"] & FLAG_UP)
            and bool(parsed_auth_reg["flags"] & FLAG_AT)
            and bool(parsed_auth_auth["flags"] & FLAG_UP),
    })


# ── Browser Extension: Wire-Format Passthrough ────────────────────────────────

def api_webauthn_create(body: dict) -> dict:
    """Handle a navigator.credentials.create() call from the browser extension.

    Accepts the serialized PublicKeyCredentialCreationOptions forwarded by the
    extension's background script and returns the full wire-format
    PublicKeyCredential response that the browser page expects.

    Expected body keys (from background.js buildRegisterBody):
        rpId, origin, userName, userDisplayName, userId (b64url), challenge
        (b64url), alg, attestation, userVerification, upAllow, uvAllow,
        excludeCredentials.
    """
    rp_id   = body.get("rpId", "example.com")
    origin  = body.get("origin", f"https://{rp_id}")
    alg     = int(body.get("alg", -7))
    uv      = body.get("userVerification", "preferred")
    up_allow = bool(body.get("upAllow", True))
    uv_allow = bool(body.get("uvAllow", True))

    # challenge and userId arrive as base64url strings from the browser;
    # PasskeyProvider._to_bytes() normalises them automatically.
    options: dict[str, Any] = {
        "rp": {
            "id":   rp_id,
            "name": body.get("rpName", rp_id),
        },
        "user": {
            "id":          body.get("userId", b64url_encode(os.urandom(16))),
            "name":        body.get("userName", "user@example.com"),
            "displayName": body.get("userDisplayName", body.get("userName", "User")),
        },
        "challenge":       body["challenge"],
        "pubKeyCredParams": [{"type": "public-key", "alg": alg}],
        "excludeCredentials": body.get("excludeCredentials", []) or [],
        "authenticatorSelection": {
            "residentKey":       "required",
            "userVerification":  uv,
        },
        "attestation": body.get("attestation", "none"),
    }

    local_provider = PasskeyProvider(
        store=_store,
        up_callback=lambda r, a: up_allow,
        uv_callback=lambda r: uv_allow,
    )

    reg = local_provider.create(options, origin)
    return _ok(reg.to_dict())


def api_webauthn_get(body: dict) -> dict:
    """Handle a navigator.credentials.get() call from the browser extension.

    Accepts the serialized PublicKeyCredentialRequestOptions forwarded by the
    extension's background script and returns the full wire-format
    PublicKeyCredential assertion response.

    Expected body keys (from background.js buildAuthenticateBody):
        rpId, origin, challenge (b64url), userVerification, allowCredentials,
        upAllow, uvAllow.
    """
    origin   = body.get("origin", "")
    # rpId is optional in the WebAuthn spec; derive from origin when absent.
    rp_id    = body.get("rpId") or (urlparse(origin).hostname if origin else "example.com")
    origin   = origin or f"https://{rp_id}"
    uv       = body.get("userVerification", "preferred")
    up_allow = bool(body.get("upAllow", True))
    uv_allow = bool(body.get("uvAllow", True))

    # allowCredentials ids arrive as b64url strings; _to_bytes() normalises.
    options: dict[str, Any] = {
        "rpId":             rp_id,
        "challenge":        body["challenge"],
        "allowCredentials": body.get("allowCredentials", []) or [],
        "userVerification": uv,
    }

    local_provider = PasskeyProvider(
        store=_store,
        up_callback=lambda r, a: up_allow,
        uv_callback=lambda r: uv_allow,
    )

    auth = local_provider.get(options, origin)
    return _ok(auth.to_dict())


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP handler
# ═══════════════════════════════════════════════════════════════════════════════

_ROUTES: dict[str, Any] = {
    "/api/reset":               api_reset,
    "/api/status":              api_status,
    "/api/credential-secret":   api_credential_secret,
    "/api/generate-keypair":    api_generate_keypair,
    "/api/sign-and-verify":     api_sign_and_verify,
    "/api/build-client-data":   api_build_client_data_json,
    "/api/pack-auth-data":      api_pack_parse_auth_data,
    "/api/validate-origin":     api_validate_origin,
    "/api/register":            api_register,
    "/api/register-duplicate":  api_register_duplicate,
    "/api/authenticate":        api_authenticate,
    "/api/error-case":          api_error_case,
    "/api/full-flow":           api_full_flow,
    # Browser extension wire-format endpoints
    "/api/webauthn/create":     api_webauthn_create,
    "/api/webauthn/get":        api_webauthn_get,
}

_FRONTEND = Path(__file__).parent / "frontend.html"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # quieter logs
        print(f"  {self.address_string()} {fmt % args}")

    def _send_json(
        self, payload: dict, status: int = 200, *, cors: bool = True
    ) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            if _FRONTEND.exists():
                self._send_html(_FRONTEND.read_bytes())
            else:
                self._send_json(_err("frontend.html not found next to this script."), 404)
        elif path == "/api/status":
            self._send_json(api_status({}))
        else:
            self._send_json(_err(f"Unknown route: {path}"), 404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        handler = _ROUTES.get(path)
        if handler is None:
            self._send_json(_err(f"Unknown route: {path}"), 404)
            return
        if path == "/api/credential-secret":
            origin = self.headers.get("Origin")
            expected_origin = f"http://{self.headers.get('Host', '')}"
            if origin != expected_origin:
                self._send_json(
                    _err("Secret keys can only be requested from the local demo page."),
                    403,
                    cors=False,
                )
                return
        try:
            body = _parse_body(self)
            result = handler(body)
            self._send_json(result, cors=path != "/api/credential-secret")
        except Exception as exc:
            tb = traceback.format_exc()
            print(tb)
            self._send_json(_err(f"{type(exc).__name__}: {exc}"), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description="pysskey testing front-end server")
    parser.add_argument("--port", type=int, default=8742, help="TCP port (default: 8742)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), _Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"\n  pysskey testing front-end")
    print(f"  ─────────────────────────")
    print(f"  Open in browser → {url}")
    print(f"  Press Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")


if __name__ == "__main__":
    main()
