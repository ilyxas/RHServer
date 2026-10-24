# contracts/ changelog

## friend slice 3: the agent answers, the phone sees the state

- `api/openapi.yaml` 0.6.0:
  - `friend.send` body gains the optional `kind` (question | task, default question; signed with the body, shown to the agent, enforced by the agent-side gate) and `re` (spool id of the message it follows up, "make it a task"). A new message supersedes every earlier one the agent still owed an answer to. The same `id` with the same body sent again by the same device (a retry) returns the first message's answer and creates nothing; the same `id` with another body is bad_request.
  - New `POST /v1/friend/messages` (`friend.messages`, normal): the owner's messages changed after `since`, with state (accepted → received → waiting → answered; rejected, superseded) and the agent's replies (`FriendMessage`, `FriendReply`); `next` / `more` for paging. The core is the source of truth: the app can be closed or offline and catch up. States after accepted and the replies are the agent side's report, not signed facts.
  - `log.list` filter chat: the owner's texts and the agent's replies as `chat.message` entries, title "owner → <agent>" / "<agent> → owner", detail = text.
- `vectors/friend.json` version 3: build cases `task` and `make-it-a-task` (the phone's encoding with `kind` and `re`), core cases `send-kind-question`, `send-task-re` (accepted), `send-kind-bad`, `send-re-bad` (bad_request). Existing cases unchanged.
- No changes to signing, key levels, other operations or WebSocket events.

## Any single agent on the channel (docs/any_single_agent.md)

- `api/openapi.yaml` 0.5.0:
  - `status` gains the required `channel: {agent, title}` (schema `Channel`): the one agent the phone talks to, `[channel] agent` in the core config. The app takes `to` and every name it shows from it; it can change between two `status` calls when the owner switches the agent.
  - `to` of `friend.send` and `FriendDecision` is no longer `const: Friend` but the channel agent's id (`^[A-Za-z0-9_-]{1,32}$`); any value other than the configured agent is `bad_request`.
  - Descriptions name "the channel agent"; "friend" stays the name of the mechanism (paths, ops, schemas), after the agent that designed it and first worked on it.
- `vectors/friend.json` version 2 and `vectors/friend_decide.json` version 3: top-level `agent` (`Agent-Alpha`, deliberately not "Friend"); every body is addressed to it; wrong-recipient cases use `Agent-Beta`. The verifier's envelope with another `to` is now blocked as `wrong_recipient` (was `bad_body`); `friend_decide.json` has the same envelope case.
- No changes to signing, operations, key levels or WebSocket events. Only the value of `to` in signed bodies changes.

## friend.decide, last round before the live test

- `vectors/friend_decide.json` version 2, `gate` section: for one action the newest decision by signed `ts` counts and a deny wins a tie. `deny-and-allow-both-present` (allowed) is replaced by `deny-and-allow-signed-at-the-same-time` (denied), `allow-then-a-newer-deny` (denied) and `deny-then-a-newer-allow` (allowed). Other sections and `friend.json` are byte for byte the same.
- No changes to `api/openapi.yaml` (0.4.0 stays), signing or WebSocket events.

## friend.decide (signed decisions for the Friend gate)

- `api/openapi.yaml` 0.4.0:
  - `GET /v1/friend/questions` (`friend.questions`, normal): open questions of the Friend session, oldest first; each has `id`, `text`, `action` (canonical JSON `{"input","tool"}` of one exact tool call) and `asked_at`. Home shows the same list as `rh.questions` rows.
  - `POST /v1/friend/decide` (`friend.decide`): body `{"to":"Friend","id","question_sha256","action","decision"}`; allow is signed with the critical key, deny with the normal key, the other way round is `wrong_key_level`. A body that does not fit, or a decision that names no open question or a different text hash or action, is `bad_request`. Accepted decisions are spooled like friend.send messages and answered with `{id, question_id, decision, accepted_at}`.
  - Schemas `FriendQuestion`, `FriendDecision`.
- New `vectors/friend_decide.json`: question text → `question_sha256`; the phone's decide body encoding; core accept/reject cases against the stage 1 fixture plus one open question; envelopes the Friend verifier must pass or block; gate cases (tool call + envelopes + core state → allow or block with code).
- No changes to signing, existing operations, existing vectors (`friend.json` is byte for byte the same) or WebSocket events.

## friend.send (signed messages to the Friend session)

- `api/openapi.yaml` 0.3.0: `POST /v1/friend` (`friend.send`, normal). Body `{"id","text","to":"Friend"}`; a body that does not fit is `bad_request`. Accepted requests are kept as received (auth header, signature, body bytes) under `spool_id` = first 32 hex of sha256(nonce) and answered with `{id, message_id, accepted_at}`.
- New `vectors/friend.json`: the phone's body encoding (sorted keys, no spaces), core accept/reject cases against the stage 1 fixture, the core's signed device list (`{"payload":"<JCS>","sig"}`) and envelopes the Friend verifier must pass or block (tampered body, wrong op, wrong `to`, wrong key level, other device's signature, unknown and revoked device, replayed nonce, too old, from the future, pointer mismatch, bad or foreign device-list signature).
- `text` has at most 8000 characters (`maxLength`; `bad_request` above), since it goes into the Friend session's context; vector `send-text-too-long`.
- No changes to signing, existing operations, existing vectors or WebSocket events.

## Stage 2, Home and Log

- `api/openapi.yaml` 0.2.0:
  - `POST /v1/data` (`data.get`, normal): a batch of data_id → value. Each value is `active` (`type`, `value`, `unit` for numbers, `at`), `pending` (not built in, not registered) or `error` (`message`). Built-in ids and their types are listed in the operation: `sys.cpu`, `sys.memory` (`%`), `sys.disk_free` (`bytes`), `rh.status` (status), `rh.approvals`, `rh.questions`, `rh.activity`, `agents.status` (rows).
  - `POST /v1/log` (`log.list`, normal): the Log feed, newest first, with `filter` (all / commands / approvals / chat / errors), `query`, an opaque `before` cursor and `limit`. Entries have `kind`, a ready-to-show `title` and `id` = sha256 of the journal line. Accepted requests are not in the feed by default (owner's decision): reads are noise, and a command shows as its effect (pairing, device revoked); `include_reads: true` lists them as kind system.
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
