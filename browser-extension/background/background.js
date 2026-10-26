/**
 * background.js — Background Script
 *
 * Handles all HTTP communication with the pysskey local server.
 * Content scripts can't fetch http://localhost directly from a cross-origin
 * page context, but background scripts can (they're not bound to any page
 * origin). The content script relays its requests here via sendMessage.
 *
 * pysskey HTTP API (demo_server.py):
 *   POST /api/webauthn/create  — PasskeyProvider.create(), returns full wire-format credential
 *   POST /api/webauthn/get     — PasskeyProvider.get(), returns full wire-format assertion
 *   POST /api/register         — diagnostic summary (not used by extension)
 *   POST /api/authenticate     — diagnostic summary (not used by extension)
 *
 * All routes return: { ok: true, data: { ... } }  or  { ok: false, error: "..." }
 */

"use strict";

// Default pysskey server address — user can change this in the popup.
const DEFAULT_SERVER = "http://127.0.0.1:8742";

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

async function getServerUrl() {
  const prefs = await browser.storage.local.get({ serverUrl: DEFAULT_SERVER });
  return prefs.serverUrl.replace(/\/$/, ""); // strip trailing slash
}

async function pysskeyPost(path, body) {
  const base = await getServerUrl();
  const url = base + path;

  let resp;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (netErr) {
    throw new Error(
      `pysskey server unreachable at ${url} — is the server running? (${netErr.message})`
    );
  }

  if (!resp.ok) {
    throw new Error(`pysskey HTTP ${resp.status} on ${path}`);
  }

  const json = await resp.json();
  if (!json.ok) {
    throw new Error(json.error || `pysskey returned ok:false from ${path}`);
  }

  return json.data;
}

// ──────────────────────────────────────────────────────────────────────────────
// Request mapping: WebAuthn options → pysskey API bodies
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Map serialized PublicKeyCredentialCreationOptions to the /api/register body.
 *
 * pysskey's /api/register body keys:
 *   rpId, origin, userName, userDisplayName, alg, attestation,
 *   userVerification, upAllow, uvAllow
 *
 * But the full options structure is richer; we POST the full options dict
 * with the additional keys the server needs.
 */
function buildRegisterBody(payload) {
  // Pick the first supported alg (prefer ES256 = -7, then EdDSA = -8)
  const SUPPORTED = new Set([-7, -8]);
  const algEntry = (payload.pubKeyCredParams || []).find(
    (p) => p.type === "public-key" && SUPPORTED.has(p.alg)
  );
  const alg = algEntry ? algEntry.alg : -7;

  const authSel = payload.authenticatorSelection || {};

  return {
    rpId: payload.rp.id,
    origin: payload.origin,
    userName: payload.user.name,
    userDisplayName: payload.user.displayName,
    userId: payload.user.id,           // b64url, forwarded for traceability
    challenge: payload.challenge,       // b64url
    alg,
    attestation: payload.attestation || "none",
    userVerification: authSel.userVerification || "preferred",
    upAllow: true,
    uvAllow: true,
    // Forward exclude list so pysskey can honour it
    excludeCredentials: (payload.excludeCredentials || []).map((c) => ({
      type: c.type,
      id: c.id, // already b64url
    })),
  };
}

/**
 * Map serialized PublicKeyCredentialRequestOptions to the /api/authenticate body.
 *
 * pysskey's /api/authenticate body keys:
 *   rpId, origin, userVerification, allowCredentials, upAllow, uvAllow
 */
function buildAuthenticateBody(payload) {
  // rpId is optional in PublicKeyCredentialRequestOptions (spec §5.1.4).
  // When the site omits it, the RP ID defaults to the origin's effective
  // domain.  Derive it here so the server never receives undefined.
  const rpId =
    payload.rpId ||
    (payload.origin ? new URL(payload.origin).hostname : undefined);
  return {
    rpId: rpId,
    origin: payload.origin,
    challenge: payload.challenge,       // b64url (forwarded for traceability)
    userVerification: payload.userVerification || "preferred",
    allowCredentials: (payload.allowCredentials || []).map((c) => ({
      type: c.type,
      id: c.id, // already b64url
    })),
    upAllow: true,
    uvAllow: true,
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Response normalisation
//
// pysskey's /api/register returns data that looks like:
//   { id, rawIdHex, transports, attestationFmt, attestationObject: {...summary}, authData: {...summary} }
//
// But we need the actual wire bytes: clientDataJSON, attestationObject base64url.
// The pysskey /api/register endpoint doesn't currently return the raw bytes
// in its summary response — we need to call a passthrough that returns the
// full RegistrationResponse.to_dict() format.
//
// Looking at demo_server.py, /api/register returns a SUMMARY dict,
// not the full PublicKeyCredential wire format. So we call a different
// endpoint: we POST to /api/register/raw (which we'll add to the server)
// OR we use the existing /api/full-flow which also doesn't return raw bytes.
//
// Instead, we implement our own thin "passthrough" server endpoint (see
// README). For now we use /api/register and /api/authenticate but ask the
// server to return the full credential bytes by adding a "returnRaw: true"
// flag. The server is extended with /api/webauthn/create and
// /api/webauthn/get endpoints in server_extension.py (see README).
// ──────────────────────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// Message handler
// ──────────────────────────────────────────────────────────────────────────────

browser.runtime.onMessage.addListener((message, sender) => {
  // Only handle messages from our own extension's content scripts
  if (!sender.tab) return;

  const { type, payload } = message;

  if (type === "pysskey_create") {
    return handleCreate(payload);
  }

  if (type === "pysskey_get") {
    return handleGet(payload);
  }

  if (type === "pysskey_status") {
    return handleStatus(payload);
  }

  // Unknown message type — let Firefox handle it (return undefined)
});

async function handleCreate(payload) {
  try {
    const body = buildRegisterBody(payload);
    const data = await pysskeyPost("/api/webauthn/create", body);
    return { ok: true, data };
  } catch (err) {
    console.error("[pysskey background] create failed:", err);
    return { ok: false, error: err.message };
  }
}

async function handleGet(payload) {
  try {
    const body = buildAuthenticateBody(payload);
    const data = await pysskeyPost("/api/webauthn/get", body);
    return { ok: true, data };
  } catch (err) {
    console.error("[pysskey background] get failed:", err);
    return { ok: false, error: err.message };
  }
}

async function handleStatus(payload) {
  try {
    const base = await getServerUrl();
    const resp = await fetch(base + "/api/status");
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = await resp.json();
    return { ok: true, data: json.data };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}
