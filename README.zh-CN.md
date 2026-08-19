# edev

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](#支持平台)
[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

**搞清楚到底是什么占着你的开发端口,然后清掉它。**

[English](README.md)

---

## 项目目的

`lsof -i :3000` 只告诉你一个 PID 和一个 `node`。这通常不够。

它是你忘了关的 Vite,是另一个项目的后端,是某个 Postgres 容器,还是系统本身要用的东西?
端口号几乎不携带信息:`8080` 可以是任何东西,而一个再正常不过的后端可能跑在 `3800` ——
任何"常见开发端口"清单都不会收录它。

edev 回答端口号回答不了的问题:它读每个监听进程的**真实启动现场** ——
完整 argv、环境变量、工作目录、父进程,以及这个端口上的活跃连接。
然后对这些证据打分,告诉你它是什么,并把推理过程摊开给你看,方便你不同意。

```console
$ edev
PORT  PROTO  ADDR       PID    PROCESS       CPU    MEM       UPTIME  CONN  PARENT
3800  tcp    *          99752  bun           0.0%~  236.3 MB  18h49m  -     bun (99751)
    ↳ bun server/index.ts · dev server(高)  ~/code/my-app
4000  tcp6   ::1        99923  bun           0.0%~  770.2 MB  18h48m  1     just (99912)
    ↳ Vite · dev server(高)  ~/code/my-app
9000  tcp    127.0.0.1  4100   llama-server  0.0%~  750.2 MB  1d23h   -     #1
    ↳ llama.cpp · 基础设施(高)

$ edev clean --all --dev-only     # 停掉 dev server,数据库不碰
```

几条设计约束决定了其余所有取舍:

- **快。** 遍历约 900 个进程,端到端约 3 ms。直接走 `libproc` 和 `sysctl` 找内核要数据,
  从不 fork `lsof`。
- **被动。** 从不向任何端口发起连接。没有探测流量,不会写进别人的访问日志,不会触发限流。
- **可解释。** 每条判定都带着产生它的证据一起给出。
- **克制。** 它只负责清理开发端口,不是通用的杀进程工具:系统组件和 edev 自身的祖先进程
  受绝对保护,没有任何开关可以放行。

## 工作管线

```mermaid
flowchart TD
    subgraph backend["platform/ —— 可替换的 OS 后端"]
        direction TB
        P1["枚举全部 PID<br/>pids_by_type"]
        P2["按 PID 并行(rayon)<br/>列 fd,读 socket 信息"]
        P3["只对候选 PID:<br/>argv + env、cwd、进程指标"]
        P1 --> P2
    end

    subgraph core["core —— 平台无关"]
        direction TB
        S1["scan.rs<br/>按 (pid, 端口) 归并<br/>统计活跃连接"]
        C1["classify.rs<br/>给证据打分"]
        S2["scan.rs<br/>保护策略"]
        S1 --> C1 --> S2
    end

    subgraph sinks["输出"]
        direction TB
        R1["render.rs<br/>表格 · 详情 · JSON"]
        R2["kill.rs<br/>SIGTERM → 宽限 → SIGKILL"]
    end

    P2 -->|"LISTEN + ESTABLISHED socket"| S1
    S1 -.->|"只剩约 20 个 PID"| P3
    P3 -->|"证据"| C1
    S2 --> R1
    S2 --> R2
```

扫描刻意不做前置过滤:枚举**全部 65535 个端口**和枚举一张白名单花的时间一样多,
而白名单唯一的作用就是漏掉你没想到的那些端口。收敛发生在之后,依据是判定结果,
不是端口号。

分类先走一条短路链,链上不中再进打分:

```mermaid
flowchart LR
    A["监听进程"] --> B{"系统组件?"}
    B -->|是| SYS["System"]
    B -->|否| C{"容器端口<br/>转发进程?"}
    C -->|是| CON["Container"]
    C -->|否| D{"已知数据库 /<br/>基础设施?"}
    D -->|是| INF["Database / Infra"]
    D -->|否| E["给证据打分:<br/>argv 里的框架名、开发模式子命令、<br/>NODE_ENV、cwd 里的项目标记、<br/>父进程、绑定地址、<br/>连接来源、运行时长"]
    E --> F{"得分 ≥ 3?"}
    F -->|是| DEV["DevServer"]
    F -->|否| UNK["Unknown"]
```

命令行和环境变量里经常夹着密钥,所以:环境变量只参与打分,之后**直接丢弃 ——
不保存、不打印,连 key 都不进 JSON**;argv 在存下来之前先脱敏,
`--api-key=xxx` 变成 `--api-key=***`,`postgres://user:pass@host` 变成
`postgres://***@host`。

## 选用依赖

刻意保持精简,每一个都得自己挣到位置:

| Crate | 为什么 |
|---|---|
| [`libproc`](https://crates.io/crates/libproc) | Darwin `proc_pidinfo` / `proc_pidfdinfo` 的安全封装。不用它就得手写几百字节的 `#[repr(C)]` socket 结构体。 |
| [`libc`](https://crates.io/crates/libc) | `sysctl(KERN_PROCARGS2)` 取 argv 和 envp,外加 `kill`、`getpwuid`、`localtime_r`、`isatty`。 |
| [`rayon`](https://crates.io/crates/rayon) | 按 PID 遍历 socket 是天然并行的,而且占了绝大部分运行时间。 |
| [`clap`](https://crates.io/crates/clap) | derive 式 CLI、子命令、自动生成 help。 |
| [`serde`](https://crates.io/crates/serde) + [`serde_json`](https://crates.io/crates/serde_json) | `--json` 输出,让 edev 能和别的工具拼起来用。 |
| [`rustc-hash`](https://crates.io/crates/rustc-hash) | 归并用的 `FxHashMap`。这里不需要抗 DoS,默认的慢哈希买不到任何东西。 |

刻意**没有**用的:不 fork `lsof`,没有异步运行时,没有 HTTP 客户端,没有 TUI 框架,
也没有终端配色 crate(`style.rs` 里 60 行 ANSI 就够了)。

## 支持平台

**目前仅 macOS。** 后端之上的所有代码都是平台无关的。

`src/platform/` 是一条刻意留出的接缝。在其他系统上编译会直接 `compile_error!`,
并写清楚一个新后端需要提供什么:

```
scan · proc_info · brief · cmdline · cwd · cpu_time_ns · ppid · self_pid · local_time
SYSTEM_SERVICE_NAMES · SYSTEM_PATH_PREFIXES · SUPERVISOR_NAME
```

Linux 上对应的是:读 `/proc/net/tcp*` 拿 socket inode,扫 `/proc/<pid>/fd` 反查 PID,
argv 和 cwd 直接读 `/proc/<pid>/cmdline` 和 `/proc/<pid>/cwd` ——
打分引擎、保护策略、渲染、清理逻辑全部原样复用。欢迎来提。

## 安装

```bash
brew install XuanLee-HEALER/tap/edev
```

或者从源码装:

```bash
cargo install --git https://github.com/XuanLee-HEALER/edev
```

release 里是通用二进制(`x86_64` + `arm64`,`MACOSX_DEPLOYMENT_TARGET=11.0`),
由 CI 从 `main` 上的 tag 构建。

## 开发

```bash
cargo fmt --check
cargo clippy --all-targets # pedantic + nursery,零警告
cargo test
```

CI 跑在 `macos-latest` 上 —— 只能这样,因为在别的系统上编译会直接停在
`src/platform/mod.rs` 的 `compile_error!`。

## 参与

欢迎 fork、拿去用、拆开改。Issue 和 PR 都欢迎,尤其是这几类:

- **Linux 或 Windows 后端。** 接缝已经留好,要实现什么上面写清楚了。
- **识别特征。** `src/classify.rs` 里的框架表、数据库表、容器表都是纯静态数据,
  把你的技术栈加进去就是一行 PR。
- **判错了。** 如果 edev 认错了什么,跑 `edev -l` 把证据块贴进 issue ——
  那段输出就是为了让错误一眼可见才设计的。

## 许可

GPL-2.0-only,见 [LICENSE](LICENSE)。
