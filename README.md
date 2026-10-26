# pysskey

pysskey is a pure-Python WebAuthn Level 2/3 client-side authenticator library. It provides a `PasskeyProvider` that handles credential creation and authentication, with pluggable credential storage and cryptographic helpers.

Hopefully this will fit into a bigger picture in the future - specifically serving as a foundation for  research.

## Features

- WebAuthn credential creation and authentication through `PasskeyProvider`.
- ES256 (`-7`) and EdDSA/Ed25519 (`-8`) key support.
- In-memory and AES-256-GCM encrypted file-backed credential stores.
- Authenticator data and COSE key encoding helpers.
- An interactive demo server and an optional Firefox extension for localhost testing.

## Requirements

- Python 3.10 or newer.
- Dependencies: `cryptography` and `cbor2`.

## Install

Install the package and development/test dependencies from the repository root:

```powershell
python -m pip install -e ".[dev]"
```

## Run the tests

```powershell
python -m pytest
```

## Interactive demo

Start the demo server from the repository root:

```powershell
python demo-server\demo_server.py
```

Open <http://127.0.0.1:8742> in a browser. The demo includes registration, authentication, crypto and authenticator-data tools, and a store inspector. The inspector lists credentials without private-key material by default. Select **Reveal secret key** on a credential to request and display its PEM private key; the separate secret endpoint is only called after that button is clicked. Select **Hide secret key** to remove the displayed value from the page.

The demo server is intended for local testing only. The inspector's secret-key endpoint does not require authentication. Keep the default loopback bind address; do not expose the server to an untrusted network. Revealed private keys are sensitive and can be used to impersonate the corresponding authenticator credential.

The server accepts `--port` and `--host` options. For example:

```powershell
python demo-server\demo_server.py --port 9000
```

## Firefox extension

The optional Manifest V2 extension is in [`firefox-extension`](./firefox-extension). Load that directory as a temporary add-on in Firefox for local testing, and run the demo server at its default localhost address. The extension forwards WebAuthn creation and authentication requests to the local server.

## Package layout

- `pysskey/provider.py` — WebAuthn credential creation and authentication flow.
- `pysskey/store.py` — credential-store interface, in-memory store, and encrypted file store.
- `pysskey/crypto.py` — key generation, signing, verification, and COSE key helpers.
- `pysskey/authenticator_data.py` — authenticator data packing and parsing.
- `pysskey/models.py` — credential and WebAuthn response data models.
- `demo-server/` — interactive HTTP demo and browser UI.
- `firefox-extension/` — optional Firefox integration.
- `tests/` — automated test suite.
