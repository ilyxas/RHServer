# Package dependencies

Static imports between packages in `src/`. Arrows point from the importer to what it uses.

```mermaid
flowchart TB
    subgraph entry["Entry points (pyproject scripts)"]
        rhcore_bin["rhcore / rhpage"]
        agent_bin["rh-agent"]
        friend_bin["rh-friend-bridge / -verify / -gate / -ask"]
    end

    subgraph rh_cli["rh_cli"]
        cli_rhcore["rhcore"]
        cli_rhpage["rhpage"]
        cli_common["_common"]
    end

    subgraph rh_agent["rh_agent (stage 3, stub)"]
        agent_main["__main__"]
    end

    subgraph rh_core["rh_core"]
        core_server["server"]
        core_app["app"]
        core_admin["admin"]
        core_store["store"]
        core_journal["journal"]
        core_pairing["pairing"]
        core_data["data"]
        core_agents["agents / agent_rules"]
        core_misc["config / keys / peers / system / logfeed"]
    end

    subgraph rh_friend["rh_friend"]
        fr_bridge["bridge"]
        fr_verify["verify"]
        fr_gate["gate"]
        fr_ask["ask"]
        fr_config["config"]
    end

    subgraph rh_common["rh_common (pure, no I/O)"]
        c_protocol["protocol"]
        c_friend["friend"]
        c_crypto["crypto"]
        c_jcs["jcs"]
    end

    rhcore_bin --> cli_rhcore & cli_rhpage
    agent_bin --> agent_main
    friend_bin --> fr_bridge & fr_verify & fr_gate & fr_ask

    cli_rhcore --> cli_common
    cli_rhpage --> cli_common
    agent_main --> cli_common
    cli_rhcore --> core_server & core_misc
    cli_rhcore -->|friend-config| fr_config
    cli_rhcore --> c_protocol

    core_server --> core_app
    core_admin --> core_app
    core_app --> core_store & core_journal & core_pairing & core_data & core_agents & core_misc
    core_app --> c_friend & c_protocol
    core_store --> c_friend
    core_data --> core_agents

    fr_gate --> fr_verify
    fr_ask --> fr_gate
    fr_bridge & fr_verify & fr_gate & fr_ask --> fr_config
    fr_bridge & fr_verify & fr_gate & fr_ask --> c_friend

    c_friend --> c_protocol
    c_protocol --> c_crypto & c_jcs
    core_journal --> c_crypto & c_jcs
```

Notes:

- `rh_common` is the only package shared by the core and the Friend side; `rh_friend`
  never imports `rh_core` (it reaches a running core only over the admin socket and the
  inbox directory, see [runtime.md](runtime.md)).
- The only import from the CLI into `rh_friend` is `rhcore friend-config`, which writes
  `friend.toml`.
