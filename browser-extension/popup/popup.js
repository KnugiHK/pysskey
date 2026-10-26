/**
 * popup.js — Popup script for pysskey WebAuthn Provider extension.
 */

"use strict";

const DEFAULT_SERVER = "http://127.0.0.1:8742";

// ── DOM refs ────────────────────────────────────────────────────────────────
const enabledToggle  = document.getElementById("enabledToggle");
const serverUrlInput = document.getElementById("serverUrl");
const saveUrlBtn     = document.getElementById("saveUrl");
const saveStatus     = document.getElementById("saveStatus");
const serverStatus   = document.getElementById("serverStatus");
const refreshBtn     = document.getElementById("refreshStatus");
const credentialList = document.getElementById("credentialList");
const credItems      = document.getElementById("credItems");

// ── Load saved preferences ─────────────────────────────────────────────────
browser.storage.local
  .get({ enabled: true, serverUrl: DEFAULT_SERVER })
  .then((prefs) => {
    enabledToggle.checked = prefs.enabled;
    serverUrlInput.value  = prefs.serverUrl;
    checkServerStatus(prefs.serverUrl);
  });

// ── Toggle enabled state ───────────────────────────────────────────────────
enabledToggle.addEventListener("change", () => {
  browser.storage.local.set({ enabled: enabledToggle.checked });
});

// ── Save server URL ────────────────────────────────────────────────────────
saveUrlBtn.addEventListener("click", () => {
  const url = serverUrlInput.value.trim();
  if (!url) return;

  browser.storage.local.set({ serverUrl: url }).then(() => {
    saveStatus.textContent = "Saved!";
    saveStatus.className   = "save-status";
    clearTimeout(saveStatus._timer);
    saveStatus._timer = setTimeout(() => {
      saveStatus.textContent = "";
    }, 2000);
    checkServerStatus(url);
  });
});

// ── Refresh status button ──────────────────────────────────────────────────
refreshBtn.addEventListener("click", () => {
  const url = serverUrlInput.value.trim() || DEFAULT_SERVER;
  checkServerStatus(url);
});

// ── Check pysskey server status ────────────────────────────────────────────
async function checkServerStatus(baseUrl) {
  serverStatus.textContent = "checking…";
  serverStatus.className   = "badge badge-unknown";
  credentialList.classList.add("hidden");

  try {
    const url = baseUrl.replace(/\/$/, "") + "/api/status";
    const resp = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = await resp.json();

    serverStatus.textContent = "online";
    serverStatus.className   = "badge badge-online";

    if (json.ok && json.data) {
      renderCredentials(json.data.credentials || []);
    }
  } catch (err) {
    serverStatus.textContent = "offline";
    serverStatus.className   = "badge badge-offline";
  }
}

function renderCredentials(creds) {
  credItems.innerHTML = "";

  if (creds.length === 0) {
    credentialList.classList.add("hidden");
    return;
  }

  credentialList.classList.remove("hidden");

  for (const c of creds) {
    const li = document.createElement("li");
    li.innerHTML = `
      <strong>${escapeHtml(c.userName || "unknown")}</strong><br>
      <span>RP: ${escapeHtml(c.rpId)}</span> &middot;
      <span>alg: ${c.alg === -7 ? "ES256" : c.alg === -8 ? "EdDSA" : c.alg}</span> &middot;
      <span>sign#${c.signCount}</span>
    `;
    credItems.appendChild(li);
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
