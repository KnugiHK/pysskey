/**
 * inject.js — Content Script
 *
 * Runs at document_start in the content script world.
 * Two jobs:
 *   1. Inject webauthn_override.js into the PAGE world so it can override
 *      navigator.credentials before any page JS runs.
 *   2. Relay messages between the page world (webauthn_override.js) and the
 *      background page (which performs the actual fetch to pysskey).
 */

(function () {
  "use strict";

  // ── 1. Inject the page-world override script ────────────────────────────

  function injectScript() {
    const script = document.createElement("script");
    script.src = browser.runtime.getURL("content/webauthn_override.js");
    // Insert as the very first child of <head> or <html> so it runs before
    // any page scripts.
    const parent = document.head || document.documentElement;
    parent.insertBefore(script, parent.firstChild);
    // Remove the script tag once it has loaded (keeps the DOM clean).
    script.addEventListener("load", () => script.remove(), { once: true });
  }

  // Only inject when the extension is enabled (check storage).
  browser.storage.local.get({ enabled: true }).then((prefs) => {
    if (prefs.enabled) {
      injectScript();
    }
  });

  // ── 2. Relay page → background → page messages ──────────────────────────

  // Listen for requests from the injected page script.
  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.__pysskey_request !== true) return;

    // Check enabled state again (user may have toggled it)
    const prefs = await browser.storage.local.get({ enabled: true });
    if (!prefs.enabled) {
      window.postMessage(
        {
          __pysskey_reply: true,
          id: event.data.id,
          ok: false,
          error: "pysskey extension is disabled",
        },
        "*"
      );
      return;
    }

    const { id, type, payload } = event.data;

    try {
      // Send to background script which does the actual HTTP request
      const response = await browser.runtime.sendMessage({
        type: "pysskey_" + type, // "pysskey_create" or "pysskey_get"
        payload,
      });

      if (response.ok) {
        window.postMessage(
          { __pysskey_reply: true, id, ok: true, data: response.data },
          "*"
        );
      } else {
        window.postMessage(
          { __pysskey_reply: true, id, ok: false, error: response.error },
          "*"
        );
      }
    } catch (err) {
      window.postMessage(
        {
          __pysskey_reply: true,
          id,
          ok: false,
          error: err.message || "pysskey background communication failed",
        },
        "*"
      );
    }
  });
})();
