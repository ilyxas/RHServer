# Runtime view

The processes that run on the Mac, the phone, and the channels between them.

```mermaid
flowchart LR
    subgraph phone["iPhone (RHClient)"]
        app["RH app<br/>keys in Secure Enclave<br/>(normal / critical)"]
    end

    subgraph mac["Mac"]
        subgraph core_proc["rh-core (launchd com.ilya.rh.core)"]
            api["app: HTTP + WebSocket API<br/>every response signed"]
            admin["admin socket<br/>admin.sock (0600)"]
            store[("store: SQLite<br/>devices, nonces,<br/>questions, decisions")]
            journal[("journal<br/>YYYYMMDD.jsonl")]
            data["data sources<br/>sys.*, agents.status, questions"]
        end

        inbox[["inbox dir<br/>signed envelopes"]]
        cli["rhcore CLI<br/>(pair, devices, friend-config)"]
        bridge["rh-friend-bridge<br/>(launchd com.ilya.rh.bridge)"]

        subgraph friend_sess["Friend session (Claude Code in tmux)"]
            verify["rh-friend-verify<br/>UserPromptSubmit hook"]
            gate["rh-friend-gate<br/>PreToolUse hook"]
            ask["rh-friend-ask"]
        end

        cfg[["friend.toml<br/>pinned core key, paths,<br/>[gate] rules"]]
        ts["tailscaled"]
    end

    app -- "signed requests over Tailscale<br/>/v1/* , /v1/ws" --> api
    api -- "whois: peer node" --> ts
    api --> store & journal
    api --> data
    api -- "friend.send / friend.decide<br/>spooled as received" --> inbox

    cli -- "JSON Lines" --> admin
    ask -- "friend.ask / withdraw" --> admin
    gate -- "friend.decision.use" --> admin
    admin --> store & journal

    bridge -- "watch" --> inbox
    bridge -- "tmux send-keys ⟦rh:id⟧" --> friend_sess
    verify -- "load + re-check signature" --> inbox
    gate -- "read decide envelopes" --> inbox
    verify & gate & ask & bridge -.-> cfg
```

Trust notes:

- The core, the inbox and the bridge are transport. The Friend hooks check the phone's
  signature themselves against the device list signed by the pinned core key, so a broken
  transport can make a message fail, never pass.
- The admin socket only keeps state (questions, one-time spending of an allow); it does
  not vouch for signatures.
