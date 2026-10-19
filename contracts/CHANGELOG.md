# contracts/ changelog

## Stage 1, real Secure Enclave signature

- `vectors/ecdsa.json`: two new cases, `secure-enclave-device` (valid) and `secure-enclave-message-changed` (invalid), with a signature exported from a real iPhone Secure Enclave key at stage 1 acceptance. Fixed data in `scripts/vectors_trust.py`; the generator checks the message is the canonical signed object for that key's device id. Existing cases are unchanged.
- `api/openapi.yaml`: the dev server description says the port may differ from 8787 and comes from the pairing string. No format changes.

## Stage 1, placeholders

- Vectors and docs carry no real names, user names or host names: fixture names are neutral (`Мой iPhone`, `Mac`, `/Users/owner/...`, `mac.tail1234.ts.net`). Only values changed, not formats. `signed_requests.json`, `server_sig.json`, `pairing.json` and `jcs.json` are regenerated, so their bytes and signatures differ.

## Stage 1

- `api/openapi.yaml` 0.1.0: `/v1/challenge`, `/v1/pair`, `/v1/ping`, `/v1/status`, `/v1/devices`, `/v1/devices/revoke`, `/v1/ws`; order of checks, HTTP status per code, pairing string, device id, fingerprint; `X-RH-Sig-Critical`; `x-rh-key: normal+critical` for pair.
- `api/events.schema.json`: signed frame `{seq, payload, sig}`, payload `{seq, type, data}`, event `hello`. Frame signatures hash the payload text instead of re-canonicalizing data, so event data may contain doubles.
- New vectors: `ecdsa.json`, `request_build.json`, `signed_requests.json`, `server_sig.json`, `pairing.json`, `ws_frames.json`.

## Stage 0

- `README.md`: layout, vector format, how the RHClient copy is verified, how contracts change.
- `api/openapi.yaml`: skeleton — signing scheme, servers (8443 production, 8787 dev), `Error` and error codes, no operations yet.
- `vectors/jcs.json`: RFC 8785 vectors, `protocol` and `full` scopes.
- `MANIFEST.sha256`: hashes of all contract files.
