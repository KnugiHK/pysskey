/**
 * webauthn_override.js
 *
 * Runs in the PAGE world (injected via a <script> tag by inject.js).
 * Overrides navigator.credentials.create() and navigator.credentials.get()
 * to route calls through the pysskey HTTP server on localhost.
 *
 * Communication back to the content script (and then to the background page
 * for the actual fetch) uses window.postMessage.
 */

(function () {
  "use strict";

  // ──────────────────────────────────────────────────────────────────────────
  // Helpers: ArrayBuffer ↔ base64url
  // ──────────────────────────────────────────────────────────────────────────

  function bufferToB64url(buffer) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  function b64urlToBuffer(b64url) {
    const padded = b64url + "=".repeat((4 - (b64url.length % 4)) % 4);
    const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Serialise PublicKeyCredentialCreationOptions for JSON transport
  // (ArrayBuffers → base64url strings)
  // ──────────────────────────────────────────────────────────────────────────

  function serializeCreateOptions(options) {
    const pk = options.publicKey;
    if (!pk) throw new Error("pysskey: options.publicKey is required");

    return {
      rp: {
        id: pk.rp.id || window.location.hostname,
        name: pk.rp.name || pk.rp.id || window.location.hostname,
      },
      user: {
        id: bufferToB64url(pk.user.id),
        name: pk.user.name,
        displayName: pk.user.displayName,
      },
      challenge: bufferToB64url(pk.challenge),
      pubKeyCredParams: pk.pubKeyCredParams || [{ type: "public-key", alg: -7 }],
      timeout: pk.timeout,
      excludeCredentials: (pk.excludeCredentials || []).map((c) => ({
        type: c.type,
        id: bufferToB64url(c.id),
        transports: c.transports,
      })),
      authenticatorSelection: pk.authenticatorSelection || {},
      attestation: pk.attestation || "none",
      extensions: pk.extensions,
      origin: window.location.origin,
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Serialise PublicKeyCredentialRequestOptions for JSON transport
  // ──────────────────────────────────────────────────────────────────────────

  function serializeGetOptions(options) {
    const pk = options.publicKey;
    if (!pk) throw new Error("pysskey: options.publicKey is required");

    return {
      rpId: pk.rpId || window.location.hostname,
      challenge: bufferToB64url(pk.challenge),
      allowCredentials: (pk.allowCredentials || []).map((c) => ({
        type: c.type,
        id: bufferToB64url(c.id),
        transports: c.transports,
      })),
      userVerification: pk.userVerification || "preferred",
      timeout: pk.timeout,
      extensions: pk.extensions,
      origin: window.location.origin,
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Reconstruct a PublicKeyCredential-like object from pysskey's response
  // ──────────────────────────────────────────────────────────────────────────

  function buildRegistrationCredential(data) {
    const rawId = b64urlToBuffer(data.rawId);
    const clientDataJSON = b64urlToBuffer(data.response.clientDataJSON);
    const attestationObject = b64urlToBuffer(data.response.attestationObject);

    // Construct a plain object that mirrors the PublicKeyCredential interface.
    // We can't call `new PublicKeyCredential(...)` directly — it's not
    // constructable. Instead we create a plain object with the correct shape.
    const credential = {
      type: "public-key",
      id: data.id,
      rawId: rawId,
      response: {
        clientDataJSON: clientDataJSON,
        attestationObject: attestationObject,
        // Implement getTransports() as required by the spec
        getTransports: () => data.transports || ["internal"],
      },
      getClientExtensionResults: () => ({}),
    };

    return credential;
  }

  function buildAuthenticationCredential(data) {
    const rawId = b64urlToBuffer(data.rawId);
    const clientDataJSON = b64urlToBuffer(data.response.clientDataJSON);
    const authenticatorData = b64urlToBuffer(data.response.authenticatorData);
    const signature = b64urlToBuffer(data.response.signature);
    const userHandle = data.response.userHandle
      ? b64urlToBuffer(data.response.userHandle)
      : null;

    const credential = {
      type: "public-key",
      id: data.id,
      rawId: rawId,
      response: {
        clientDataJSON: clientDataJSON,
        authenticatorData: authenticatorData,
        signature: signature,
        userHandle: userHandle,
        // Implement authenticator transport hints method
        getTransports: () => ["internal"],
      },
      getClientExtensionResults: () => ({}),
    };

    return credential;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Message-based RPC to the content script (which relays to the background)
  // ──────────────────────────────────────────────────────────────────────────

  let _pendingRequests = new Map(); // id → { resolve, reject }
  let _nextId = 1;

  window.addEventListener("message", (event) => {
    // Only accept replies from the content script (same window, same origin)
    if (event.source !== window) return;
    if (!event.data || event.data.__pysskey_reply !== true) return;

    const { id, ok, data, error } = event.data;
    const pending = _pendingRequests.get(id);
    if (!pending) return;
    _pendingRequests.delete(id);

    if (ok) {
      pending.resolve(data);
    } else {
      pending.reject(new DOMException(error || "pysskey request failed", "NotAllowedError"));
    }
  });

  function sendToPysskey(type, payload) {
    return new Promise((resolve, reject) => {
      const id = _nextId++;
      _pendingRequests.set(id, { resolve, reject });
      window.postMessage(
        { __pysskey_request: true, id, type, payload },
        window.location.origin === "null" ? "*" : window.location.origin
      );
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Intercept navigator.credentials.create()
  // ──────────────────────────────────────────────────────────────────────────

  const _originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const _originalGet = navigator.credentials.get.bind(navigator.credentials);

  async function pysskeyCreate(options) {
    // Only intercept public-key requests
    if (!options || !options.publicKey) {
      return _originalCreate(options);
    }

    console.debug("[pysskey] Intercepting navigator.credentials.create()", options);

    let serialized;
    try {
      serialized = serializeCreateOptions(options);
    } catch (err) {
      console.error("[pysskey] Failed to serialize create options:", err);
      throw err;
    }

    let responseData;
    try {
      responseData = await sendToPysskey("create", serialized);
    } catch (err) {
      console.error("[pysskey] create RPC failed:", err);
      throw err;
    }

    console.debug("[pysskey] create() response:", responseData);
    return buildRegistrationCredential(responseData);
  }

  async function pysskeyGet(options) {
    // Only intercept public-key requests
    if (!options || !options.publicKey) {
      return _originalGet(options);
    }

    console.debug("[pysskey] Intercepting navigator.credentials.get()", options);

    let serialized;
    try {
      serialized = serializeGetOptions(options);
    } catch (err) {
      console.error("[pysskey] Failed to serialize get options:", err);
      throw err;
    }

    let responseData;
    try {
      responseData = await sendToPysskey("get", serialized);
    } catch (err) {
      console.error("[pysskey] get RPC failed:", err);
      throw err;
    }

    console.debug("[pysskey] get() response:", responseData);
    return buildAuthenticationCredential(responseData);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Patch navigator.credentials
  // ──────────────────────────────────────────────────────────────────────────

  try {
    // Use Object.defineProperty to make the override non-enumerable and
    // survive simple property checks by site JS.
    Object.defineProperty(navigator.credentials, "create", {
      value: pysskeyCreate,
      writable: true,
      configurable: true,
    });

    Object.defineProperty(navigator.credentials, "get", {
      value: pysskeyGet,
      writable: true,
      configurable: true,
    });

    console.info("[pysskey] WebAuthn provider active — navigator.credentials intercepted.");
  } catch (err) {
    console.error("[pysskey] Failed to override navigator.credentials:", err);
  }
})();
