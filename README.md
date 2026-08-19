# edev

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](#supported-platforms)
[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

**Find out what is actually holding your dev ports — then clean it up.**

[中文文档](README.zh-CN.md)

---

## Why

`lsof -i :3000` tells you a PID and the word `node`. That is rarely enough.

Is it the Vite dev server you forgot about, the API server from another project,
a Postgres container, or something the OS needs? A port number carries almost no
information: `8080` can be anything, and a perfectly ordinary backend can sit on
`3800`, which no "common dev ports" list will ever contain.

edev answers the question the port number cannot, by reading each listening
process's **actual launch context** — its full argv, its environment, its working
directory, its parent process, and the live connections on the port. It then
scores that evidence and tells you what the thing is, with the reasoning shown so
you can disagree with it.

```console
$ edev
PORT  PROTO  ADDR       PID    PROCESS       CPU    MEM       UPTIME  CONN  PARENT
3800  tcp    *          99752  bun           0.0%~  236.3 MB  18h49m  -     bun (99751)
    ↳ bun server/index.ts · dev server(high)  ~/code/my-app
4000  tcp6   ::1        99923  bun           0.0%~  770.2 MB  18h48m  1     just (99912)
    ↳ Vite · dev server(high)  ~/code/my-app
9000  tcp    127.0.0.1  4100   llama-server  0.0%~  750.2 MB  1d23h   -     #1
    ↳ llama.cpp · infrastructure(high)

$ edev clean --all --dev-only     # stop the dev servers, leave the database alone
```

Design constraints that shaped everything else:

- **Fast.** ~3 ms end to end across ~900 processes. It talks to the kernel
  directly via `libproc` and `sysctl` — it never shells out to `lsof`.
- **Passive.** It never opens a socket to anything. No probe traffic, no entries
  in anyone's access log, no rate limits tripped.
- **Explainable.** Every verdict ships with the evidence that produced it.
- **Narrow.** It cleans up dev ports. It is not a general-purpose process killer:
  system components and edev's own ancestors are protected with no override flag.

## How it works

```mermaid
flowchart TD
    subgraph backend["platform/ — swappable OS backend"]
        direction TB
        P1["enumerate every PID<br/>pids_by_type"]
        P2["per PID, in parallel via rayon<br/>list fds, read socket info"]
        P3["for candidate PIDs only:<br/>argv + env, cwd, proc stats"]
        P1 --> P2
    end

    subgraph core["core — platform independent"]
        direction TB
        S1["scan.rs<br/>group by (pid, port)<br/>tally live connections"]
        C1["classify.rs<br/>score the evidence"]
        S2["scan.rs<br/>protection policy"]
        S1 --> C1 --> S2
    end

    subgraph sinks["output"]
        direction TB
        R1["render.rs<br/>table · detail · JSON"]
        R2["kill.rs<br/>SIGTERM → grace → SIGKILL"]
    end

    P2 -->|"LISTEN + ESTABLISHED sockets"| S1
    S1 -.->|"only ~20 PIDs survive"| P3
    P3 -->|"evidence"| C1
    S2 --> R1
    S2 --> R2
```

The scan is deliberately unfiltered: enumerating **all 65535 ports** costs the
same few milliseconds as enumerating a whitelist, and a whitelist can only ever
lose you the ports you did not think of. Narrowing happens afterwards, on the
verdict — not on the port number.

Classification runs as a short-circuit chain, then a scoring pass:

```mermaid
flowchart LR
    A["listening process"] --> B{"system<br/>component?"}
    B -->|yes| SYS["System"]
    B -->|no| C{"container<br/>port forwarder?"}
    C -->|yes| CON["Container"]
    C -->|no| D{"known db or<br/>infra binary?"}
    D -->|yes| INF["Database / Infra"]
    D -->|no| E["weigh the evidence:<br/>framework in argv, dev subcommand,<br/>NODE_ENV, project markers in cwd,<br/>parent process, bind address,<br/>connection origin, uptime"]
    E --> F{"score ≥ 3?"}
    F -->|yes| DEV["DevServer"]
    F -->|no| UNK["Unknown"]
```

Command lines and environment variables routinely carry secrets, so: environment
variables are used for scoring and then **discarded — never stored, never
printed, not even their keys**; argv is redacted before it is kept, turning
`--api-key=xxx` into `--api-key=***` and `postgres://user:pass@host` into
`postgres://***@host`.

## Dependencies

Kept deliberately small. Every one of these earns its place:

| Crate | Why |
|---|---|
| [`libproc`](https://crates.io/crates/libproc) | Safe bindings over Darwin's `proc_pidinfo` / `proc_pidfdinfo`. The alternative was hand-rolling several hundred bytes of `#[repr(C)]` socket structs. |
| [`libc`](https://crates.io/crates/libc) | `sysctl(KERN_PROCARGS2)` for argv and envp, plus `kill`, `getpwuid`, `localtime_r`, `isatty`. |
| [`rayon`](https://crates.io/crates/rayon) | The per-PID socket walk is embarrassingly parallel and dominates runtime. |
| [`clap`](https://crates.io/crates/clap) | Derive-based CLI, subcommands, generated help. |
| [`serde`](https://crates.io/crates/serde) + [`serde_json`](https://crates.io/crates/serde_json) | `--json` output, so edev composes with other tools. |
| [`rustc-hash`](https://crates.io/crates/rustc-hash) | `FxHashMap` for the grouping tables — no DoS-resistance needed here, so the slower default hasher buys nothing. |

Notably **not** used: no `lsof` subprocess, no async runtime, no HTTP client, no
TUI framework, no terminal-color crate (60 lines of ANSI in `style.rs` covers it).

## Supported platforms

**macOS only, today.** Everything above the backend is platform independent.

`src/platform/` is a deliberate seam. Building on another OS fails with a
`compile_error!` that names exactly what a new backend has to provide:

```
scan · proc_info · brief · cmdline · cwd · cpu_time_ns · ppid · self_pid · local_time
SYSTEM_SERVICE_NAMES · SYSTEM_PATH_PREFIXES · SUPERVISOR_NAME
```

For Linux that is `/proc/net/tcp*` for socket inodes, `/proc/<pid>/fd` to map them
back to PIDs, and direct reads of `/proc/<pid>/cmdline` and `/proc/<pid>/cwd` — the
scoring engine, protection policy, rendering, and cleanup logic are all reused
untouched. Contributions welcome.

## Building

```bash
cargo install --path .     # → ~/.cargo/bin/edev
cargo fmt --check
cargo clippy --all-targets # pedantic + nursery, zero warnings
cargo test
```

## Contributing

Fork it, use it, take it apart. Issues and pull requests are welcome — especially:

- **A Linux or Windows backend.** The seam is ready and documented above.
- **Detection signatures.** The framework, database, and container tables in
  `src/classify.rs` are plain static data; adding your stack is a one-line PR.
- **Bad verdicts.** If edev mislabels something, run `edev -l` and open an issue
  with the evidence block — that output is designed to make the mistake obvious.

## License

GPL-2.0-only. See [LICENSE](LICENSE).
