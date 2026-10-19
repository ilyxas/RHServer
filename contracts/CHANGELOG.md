# contracts/ changelog

## Stage 2, Home and Log

- `api/openapi.yaml` 0.2.0:
  - `POST /v1/data` (`data.get`, normal): a batch of data_id → value. Each value is `active` (`type`, `value`, `unit` for numbers, `at`), `pending` (not built in, not registered) or `error` (`message`). Built-in ids and their types are listed in the operation: `sys.cpu`, `sys.memory` (`%`), `sys.disk_free` (`bytes`), `rh.status` (status), `rh.approvals`, `rh.questions`, `rh.activity`, `agents.status` (rows).
  - `POST /v1/log` (`log.list`, normal): the Log feed, newest first, with `filter` (all / commands / approvals / chat / errors), `query`, an opaque `before` cursor and `limit`. Entries have `kind`, a ready-to-show `title` and `id` = sha256 of the journal line. Accepted requests are not in the feed: reads are noise, and a command shows as its effect (pairing, device revoked).
  - `GET /v1/quick` (`quick.list`, normal): Quick Access items; always empty until stage 5.
  - Schemas `DataId`, `DataResult`, `StatusValue`, `Row`, `LogEntry`, `QuickItem`. `Row.status` is a `StatusValue` (SPEC §7.3 leaves its shape open). `Row.at` is an optional timestamp (owner's decision): `rh.activity` rows carry it, and Home "Last Activity" reads `rh.activity`.
  - New error code `bad_request` (400): the signature checks passed but the body does not fit the operation. Used by stage 2 operations onwards; stage 1 operations keep their behaviour.
  - Reads with parameters are POST, so the parameters are covered by the signed `body` hash.
  - Examples on the new operations; a server test validates every example against its schema.
- No changes to signing, vectors or WebSocket events.

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
