# Runtime view

The processes that run on the Mac, the phone, and the channels between them.
Dashed: the optional legacy gate (not part of a standard install).

```mermaid
flowchart LR
    subgraph phone["iPhone (RHClient)"]
        app["RH app<br/>keys in Secure Enclave<br/>(normal / critical)"]
    end

    subgraph mac["Mac"]
        subgraph core_proc["rh-core (launchd com.ilya.rh.core)"]
            api["app: HTTP + WebSocket API<br/>every response signed"]
            admin["admin socket<br/>admin.sock (0600)"]
            store[("store: SQLite<br/>devices, nonces, messages + state,<br/>replies, questions, decisions")]
            journal[("journal<br/>YYYYMMDD.jsonl")]
            data["data sources<br/>sys.*, agents.status"]
        end

        inbox[["inbox dir<br/>signed envelopes"]]
        cli["rhcore CLI<br/>(pair, devices, friend-config,<br/>channel set)"]
        bridge["rh-friend-bridge<br/>(launchd com.ilya.rh.bridge)"]

        subgraph agent_sess["Agent session (Claude Code in tmux)"]
            verify["rh-friend-verify<br/>UserPromptSubmit hook"]
            reply["rh-friend-reply<br/>Stop hook / --progress / --flush"]
            gate["rh-friend-gate + rh-friend-ask<br/>(optional legacy)"]
        end

        state[["project state/<br/>reply target (rh_current.json),<br/>pending replies (rh_pending.jsonl)"]]
        cfg[["agent config (friend.toml)<br/>pinned core key, paths,<br/>admin_socket, [bridge]"]]
        ts["tailscaled"]
    end

    app -- "signed requests over Tailscale<br/>/v1/friend, /v1/friend/messages, /v1/ws" --> api
    api -- "whois: peer node" --> ts
    api --> store & journal
    api --> data
    api -- "friend.send / friend.decide<br/>spooled as received" --> inbox

    cli -- "JSON Lines" --> admin
    verify -- "friend.received / friend.rejected" --> admin
    reply -- "friend.reply" --> admin
    gate -.-> admin
    admin --> store & journal

    bridge -- "watch" --> inbox
    bridge -- "Escape, then tmux send-keys ⟦rh:id⟧" --> agent_sess
    verify -- "load + re-check signature" --> inbox
    gate -.-> inbox
    verify -- "write reply target" --> state
    reply -- "read target, queue on failure" --> state
    verify & reply & bridge -.-> cfg

    classDef optional stroke-dasharray: 5 5
    class gate optional
```

Trust notes:

- The core, the inbox and the bridge are transport. The verifier checks the phone's
  signature itself against the device list signed by the pinned core key, so a broken
  transport can make a message fail, never pass.
- Replies are not signed: `friend.reply` over the admin socket is what the agent reports.
  The app says so ("states and replies are what Friend reports, not verified facts").
- Without the gate, what the agent may do is decided by its own permissions and
  instructions; RH adds no tool-call checks.
