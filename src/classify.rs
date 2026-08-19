//! 判定一个监听进程到底是不是 dev server。
//!
//! 端口号本身几乎没有信息量 —— 8080 可以是任何东西。真正能区分的是启动现场:
//! 命令行里的框架名、工作目录里的项目标记文件、谁把它拉起来的、环境变量、
//! 以及这个端口上实际有没有连接、连接来自哪。
//!
//! 打分制而非硬规则,每条命中都留一句人能读的证据,判断错了用户自己看得出来。

use crate::model::{ConnStats, ProcInfo};
use crate::platform::ProcArgs;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// 开发服务器 / 本地起的应用。
    DevServer,
    /// 数据库。
    Database,
    /// 中间件、消息队列、对象存储之类的基础设施。
    Infra,
    /// 容器 / 虚拟机的端口转发器,真正的服务在里面。
    Container,
    /// 系统组件。
    System,
    /// 证据不足。
    Unknown,
}

impl Kind {
    /// 全部取值,给按 `Kind` 分桶计数的地方用。
    pub const ALL: [Self; 6] = [
        Self::DevServer,
        Self::Database,
        Self::Infra,
        Self::Container,
        Self::System,
        Self::Unknown,
    ];

    /// 在 [`Self::ALL`] 里的下标。
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::DevServer => 0,
            Self::Database => 1,
            Self::Infra => 2,
            Self::Container => 3,
            Self::System => 4,
            Self::Unknown => 5,
        }
    }

    /// 默认视图里要不要显示。系统组件和判不出来的藏起来,免得刷屏。
    #[must_use]
    pub const fn shown_by_default(self) -> bool {
        matches!(self, Self::DevServer | Self::Database | Self::Infra | Self::Container)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DevServer => "dev server",
            Self::Database => "数据库",
            Self::Infra => "基础设施",
            Self::Container => "容器转发",
            Self::System => "系统组件",
            Self::Unknown => "未知",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "高",
            Self::Medium => "中",
            Self::Low => "低",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub kind: Kind,
    /// 认出来的框架 / 软件名。
    pub label: Option<String>,
    pub confidence: Confidence,
    pub score: i32,
    /// 人能读的判定依据,按命中顺序。
    pub evidence: Vec<String>,
    /// 推断出的项目根目录。
    pub project: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    /// 已脱敏的命令行。
    pub argv: Vec<String>,
}

// ---------------------------------------------------------------------------
// 特征表
// ---------------------------------------------------------------------------

/// 框架特征。先比可执行文件名,再比 `argv[1..]` —— 命中 +5 分,不是直接定案。
///
/// 必须两边都比:`vite` 这类由 node 拉起的在 argv 里,`hugo` / `air` 这类原生
/// 二进制的名字只会出现在可执行文件名和 `argv[0]`。
static FRAMEWORKS: &[(&str, &str)] = &[
    ("vite", "Vite"),
    ("next", "Next.js"),
    ("nuxt", "Nuxt"),
    ("astro", "Astro"),
    ("remix", "Remix"),
    ("webpack-dev-server", "webpack-dev-server"),
    ("webpack", "webpack"),
    ("react-scripts", "Create React App"),
    ("ng", "Angular CLI"),
    ("vue-cli-service", "Vue CLI"),
    ("svelte-kit", "SvelteKit"),
    ("parcel", "Parcel"),
    ("rollup", "Rollup"),
    ("esbuild", "esbuild"),
    ("storybook", "Storybook"),
    ("start-storybook", "Storybook"),
    ("nodemon", "nodemon"),
    ("ts-node", "ts-node"),
    ("tsx", "tsx"),
    ("live-server", "live-server"),
    ("http-server", "http-server"),
    ("serve", "serve"),
    ("expo", "Expo"),
    ("metro", "Metro"),
    ("rails", "Rails"),
    ("puma", "Puma"),
    ("unicorn", "Unicorn"),
    ("jekyll", "Jekyll"),
    ("manage.py", "Django"),
    ("runserver", "Django"),
    ("uvicorn", "Uvicorn"),
    ("gunicorn", "Gunicorn"),
    ("hypercorn", "Hypercorn"),
    ("daphne", "Daphne"),
    ("flask", "Flask"),
    ("fastapi", "FastAPI"),
    ("http.server", "python http.server"),
    ("SimpleHTTPServer", "python http.server"),
    ("streamlit", "Streamlit"),
    ("gradio", "Gradio"),
    ("jupyter", "Jupyter"),
    ("jupyter-lab", "JupyterLab"),
    ("notebook", "Jupyter Notebook"),
    ("hugo", "Hugo"),
    ("mkdocs", "MkDocs"),
    ("docusaurus", "Docusaurus"),
    ("phx.server", "Phoenix"),
    ("air", "air (Go)"),
    ("trunk", "Trunk"),
    ("dioxus", "Dioxus"),
    ("wrangler", "Wrangler"),
    ("firebase", "Firebase Emulator"),
    ("supabase", "Supabase"),
    ("artisan", "Laravel"),
    ("symfony", "Symfony"),
    ("quarkus", "Quarkus"),
    ("spring-boot", "Spring Boot"),
    ("vitest", "Vitest"),
    ("playwright", "Playwright"),
    ("cypress", "Cypress"),
];

/// 数据库 / 基础设施。一票认定,不参与打分。
///
/// 先比可执行文件名;不中再比 `argv[1..]`,好认出 `java -jar ...` 这种壳进程。
static SERVICES: &[(&str, &str, Kind)] = &[
    ("postgres", "PostgreSQL", Kind::Database),
    ("postmaster", "PostgreSQL", Kind::Database),
    ("mysqld", "MySQL", Kind::Database),
    ("mariadbd", "MariaDB", Kind::Database),
    ("redis-server", "Redis", Kind::Database),
    ("valkey-server", "Valkey", Kind::Database),
    ("dragonfly", "Dragonfly", Kind::Database),
    ("mongod", "MongoDB", Kind::Database),
    ("influxd", "InfluxDB", Kind::Database),
    ("clickhouse-server", "ClickHouse", Kind::Database),
    ("cockroach", "CockroachDB", Kind::Database),
    ("surreal", "SurrealDB", Kind::Database),
    ("qdrant", "Qdrant", Kind::Database),
    ("meilisearch", "Meilisearch", Kind::Database),
    ("typesense-server", "Typesense", Kind::Database),
    ("memcached", "memcached", Kind::Infra),
    ("nats-server", "NATS", Kind::Infra),
    ("etcd", "etcd", Kind::Infra),
    ("consul", "Consul", Kind::Infra),
    ("minio", "MinIO", Kind::Infra),
    ("nginx", "nginx", Kind::Infra),
    ("caddy", "Caddy", Kind::Infra),
    ("haproxy", "HAProxy", Kind::Infra),
    ("traefik", "Traefik", Kind::Infra),
    ("envoy", "Envoy", Kind::Infra),
    ("ollama", "Ollama", Kind::Infra),
    ("llama-server", "llama.cpp", Kind::Infra),
    ("vllm", "vLLM", Kind::Infra),
];

/// 容器 / 虚拟机的端口转发器。
static CONTAINER_HOSTS: &[(&str, &str)] = &[
    ("com.docker.backend", "Docker Desktop"),
    ("docker-proxy", "Docker"),
    ("vpnkit", "Docker Desktop"),
    ("OrbStack", "OrbStack"),
    ("orbstack-helper", "OrbStack"),
    ("colima", "Colima"),
    ("limactl", "Lima"),
    ("podman", "Podman"),
    ("socket_vmnet", "socket_vmnet"),
];

/// 交互式起进程的父进程 —— 强 dev 信号。
static INTERACTIVE_PARENTS: &[&str] = &[
    "zsh",
    "bash",
    "fish",
    "sh",
    "dash",
    "tmux",
    "screen",
    "npm",
    "pnpm",
    "yarn",
    "bun",
    "npx",
    "make",
    "just",
    "turbo",
    "nx",
    "foreman",
    "overmind",
    "hivemind",
    "concurrently",
    "mise",
    "direnv",
    "watchexec",
    "cargo-watch",
    "cargo",
    "mix",
    "rake",
    "poetry",
    "uv",
    "pdm",
    "hatch",
];

/// 项目根的标记文件。
static PROJECT_MARKERS: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
    "mix.exs",
    "pubspec.yaml",
    "deno.json",
    "build.gradle",
    "pom.xml",
    ".git",
];

/// 开发模式的子命令与开关。
static DEV_TOKENS: &[&str] =
    &["dev", "serve", "watch", "runserver", "--watch", "--hot", "--hmr", "--reload", "--dev"];

/// 值本身就说明环境的变量。
static ENV_MODE_KEYS: &[&str] =
    &["NODE_ENV", "RAILS_ENV", "RACK_ENV", "APP_ENV", "FLASK_ENV", "ENVIRONMENT", "DENO_ENV"];

/// 由包管理器脚本拉起时会注入的变量前缀。
static ENV_TOOL_PREFIXES: &[&str] =
    &["npm_", "pnpm_", "yarn_", "BUN_", "VITE_", "NEXT_", "NUXT_", "EXPO_", "TURBO_", "STORYBOOK_"];

// ---------------------------------------------------------------------------
// 判定
// ---------------------------------------------------------------------------

pub struct Input<'a> {
    pub proc: &'a ProcInfo,
    pub parent_name: Option<&'a str>,
    pub args: Option<&'a ProcArgs>,
    pub cwd: Option<&'a Path>,
    pub conns: &'a ConnStats,
    pub loopback_only: bool,
    /// 系统组件的身份判定理由,来自 [`crate::scan::system_component`]。
    pub system: Option<&'static str>,
}

/// 打分并给出判定。
#[must_use]
pub fn classify(input: &Input<'_>) -> Verdict {
    let mut ev: Vec<String> = Vec::new();
    let argv = input.args.map(|a| redact_argv(&a.argv)).unwrap_or_default();
    let exe_name = input.proc.name.as_str();
    // 找项目根要 stat 十几个路径,整个判定只算一次。
    let project = input.cwd.and_then(find_project_root);

    // --- 先看有没有一锤定音的身份 ---
    if let Some(why) = input.system {
        return verdict(Kind::System, None, 0, vec![why.to_owned()], input, project, argv);
    }
    if let Some((_, label)) = CONTAINER_HOSTS.iter().find(|(n, _)| exe_name.starts_with(n)) {
        ev.push(format!("{label} 的端口转发进程 —— 真正的服务在容器里"));
        return verdict(Kind::Container, Some((*label).to_owned()), 0, ev, input, project, argv);
    }
    if let Some((_, label, kind)) = match_service(exe_name, &argv) {
        ev.push(format!("可执行文件是 {label}"));
        let _ = conn_evidence(*input.conns, &mut ev);
        return verdict(kind, Some(label.to_owned()), 0, ev, input, project, argv);
    }

    // --- 打分 ---
    let mut score = 0;
    let mut label = None;

    if let Some((needle, name)) = match_framework(exe_name, &argv) {
        score += 5;
        label = Some(name.to_owned());
        ev.push(format!("命令行里有 {needle} —— {name}"));
    }
    if let Some(tok) = argv.iter().skip(1).find(|a| DEV_TOKENS.contains(&a.as_str())) {
        score += 2;
        ev.push(format!("跑的是 `{tok}` 这种开发模式子命令"));
    }

    if let Some(dir) = input.cwd {
        if let Some((root, marker)) = &project {
            score += 3;
            ev.push(format!("工作目录在项目里({}/{marker})", root.display()));
        } else if is_under_home(dir) {
            score += 1;
            ev.push(format!("工作目录在 home 下({})", dir.display()));
        }
        if dir == Path::new("/") {
            score -= 2;
            ev.push("工作目录是 / —— 常驻服务的典型特征".to_owned());
        }
    }

    match input.parent_name {
        Some(p) if p == crate::platform::SUPERVISOR_NAME => {
            score -= 3;
            ev.push(format!("由 {p} 托管,像开机自启的常驻服务"));
        }
        Some(p) if INTERACTIVE_PARENTS.contains(&p) => {
            score += 3;
            ev.push(format!("父进程是 {p} —— 手动或任务运行器拉起来的"));
        }
        _ => {}
    }
    if input.proc.ppid == 1 && input.parent_name.is_none() {
        score -= 2;
        ev.push("父进程是 pid 1,像被托管的常驻服务".to_owned());
    }

    score += env_score(input.args, &mut ev);

    if input.loopback_only {
        score += 1;
        ev.push("只绑回环地址,不对外提供服务".to_owned());
    }
    if input.proc.uptime_secs < 6 * 3600 {
        score += 1;
        ev.push("起来不到 6 小时".to_owned());
    } else if input.proc.uptime_secs > 3 * 86400 {
        score -= 1;
        ev.push("已经跑了 3 天以上".to_owned());
    }

    score += conn_evidence(*input.conns, &mut ev);

    let kind = if score >= 3 { Kind::DevServer } else { Kind::Unknown };
    if label.is_none() && kind == Kind::DevServer {
        // 光一个 `bun` 没法认;`bun server/index.ts` 一眼就知道是哪个服务。
        label = Some(entry_label(exe_name, &argv).unwrap_or_else(|| exe_name.to_owned()));
    }
    verdict(kind, label, score, ev, input, project, argv)
}

fn verdict(
    kind: Kind,
    label: Option<String>,
    score: i32,
    evidence: Vec<String>,
    input: &Input<'_>,
    project: Option<(PathBuf, &'static str)>,
    argv: Vec<String>,
) -> Verdict {
    let confidence = match kind {
        Kind::System | Kind::Container | Kind::Database | Kind::Infra => Confidence::High,
        Kind::DevServer if score >= 7 => Confidence::High,
        Kind::DevServer => Confidence::Medium,
        Kind::Unknown => Confidence::Low,
    };
    Verdict {
        kind,
        label,
        confidence,
        score,
        evidence,
        project: project.map(|(root, _)| root),
        cwd: input.cwd.map(Path::to_path_buf),
        argv,
    }
}

/// 没认出框架时,拿入口脚本给标签补上信息量。
fn entry_label(exe: &str, argv: &[String]) -> Option<String> {
    let script = argv.iter().skip(1).find(|a| is_script_path(a))?;
    Some(format!("{exe} {}", tail_components(script, 2)))
}

/// 看着像脚本入口的参数(排除 `--flag`)。
fn is_script_path(arg: &str) -> bool {
    if arg.starts_with('-') {
        return false;
    }
    let base = arg.rsplit('/').next().unwrap_or(arg);
    base.rsplit_once('.').is_some_and(|(_, ext)| {
        matches!(
            ext,
            "js" | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
                | "py"
                | "rb"
                | "go"
                | "php"
                | "exs"
                | "lua"
        )
    })
}

/// 保留路径末尾 n 段,`a/b/server/index.ts` -> `server/index.ts`。
fn tail_components(path: &str, n: usize) -> String {
    let mut parts: Vec<&str> = path.rsplit('/').take(n).collect();
    parts.reverse();
    parts.join("/")
}

/// argv 里每个词都拆成 {原样, basename, 去扩展名的 basename} 三个候选来匹配。
fn candidates(arg: &str) -> [&str; 3] {
    let base = arg.rsplit('/').next().unwrap_or(arg);
    let stem = base.rsplit_once('.').map_or(base, |(head, ext)| {
        if matches!(ext, "js" | "mjs" | "cjs" | "ts" | "py" | "rb" | "sh" | "exe") {
            head
        } else {
            base
        }
    });
    [arg, base, stem]
}

fn match_framework(exe: &str, argv: &[String]) -> Option<(&'static str, &'static str)> {
    lookup(FRAMEWORKS, exe, argv, |&(n, _)| n).map(|&(n, l)| (n, l))
}

fn match_service(exe: &str, argv: &[String]) -> Option<(&'static str, &'static str, Kind)> {
    lookup(SERVICES, exe, argv, |&(n, _, _)| n).map(|&(n, l, k)| (n, l, k))
}

/// 在特征表里查:先比可执行文件名,再比 `argv[1..]`,最后比 `python -m` 的模块根名。
///
/// `argv[0]` 不单独比 —— 它要么等于 exe(已经比过),要么是 node/bun 这种
/// 只说明运行时的解释器名。
fn lookup<'t, T>(
    table: &'t [T],
    exe: &str,
    argv: &[String],
    needle: impl Fn(&T) -> &'static str + Copy,
) -> Option<&'t T> {
    let hit = |cands: [&str; 3]| table.iter().find(move |row| cands.contains(&needle(row)));
    if let Some(row) = hit(candidates(exe)) {
        return Some(row);
    }
    if let Some(row) = argv.iter().skip(1).find_map(|arg| hit(candidates(arg))) {
        return Some(row);
    }
    let head = module_head(argv)?;
    table.iter().find(|row| needle(row) == head)
}

/// `python -m vllm.entrypoints.openai.api_server` 里的模块根名 `vllm`。
fn module_head(argv: &[String]) -> Option<&str> {
    let idx = argv.iter().position(|a| a == "-m")?;
    let module = argv.get(idx + 1)?;
    Some(module.split('.').next().unwrap_or(module))
}

fn env_score(args: Option<&ProcArgs>, ev: &mut Vec<String>) -> i32 {
    let Some(args) = args else {
        return 0;
    };
    let mut score = 0;
    for (k, v) in &args.env {
        if ENV_MODE_KEYS.contains(&k.as_str()) {
            let lower = v.to_ascii_lowercase();
            if matches!(lower.as_str(), "development" | "dev" | "local" | "test") {
                score += 3;
                ev.push(format!("环境变量 {k}={v}"));
            } else if lower == "production" {
                score -= 3;
                ev.push(format!("环境变量 {k}={v}"));
            }
        }
    }
    if let Some(prefix) =
        ENV_TOOL_PREFIXES.iter().find(|p| args.env.iter().any(|(k, _)| k.starts_with(**p)))
    {
        score += 2;
        ev.push(format!("环境里有 {prefix}* 变量 —— 由包管理器脚本启动"));
    }
    score
}

/// 追加连接相关的证据,并返回它对得分的贡献。
///
/// 身份已定的路径(数据库 / 容器)只要证据,忽略返回值即可。
fn conn_evidence(conns: ConnStats, ev: &mut Vec<String>) -> i32 {
    if conns.total == 0 {
        return 0;
    }
    if conns.external == 0 {
        ev.push(format!("{} 条活跃连接,全部来自本机", conns.total));
        1
    } else {
        ev.push(format!("{} 条活跃连接,其中 {} 条来自外部主机", conns.total, conns.external));
        -1
    }
}

/// 从 cwd 往上找不超过 4 层,遇到标记文件就当项目根。
fn find_project_root(start: &Path) -> Option<(PathBuf, &'static str)> {
    let mut dir = start;
    for _ in 0..4 {
        for marker in PROJECT_MARKERS {
            if dir.join(marker).exists() {
                return Some((dir.to_path_buf(), marker));
            }
        }
        dir = dir.parent()?;
    }
    None
}

fn is_under_home(dir: &Path) -> bool {
    std::env::var_os("HOME").is_some_and(|h| dir.starts_with(Path::new(&h)))
}

// ---------------------------------------------------------------------------
// 脱敏
// ---------------------------------------------------------------------------

/// 命令行里常夹着密钥,展示前先遮掉。
static SECRET_HINTS: &[&str] =
    &["key", "token", "secret", "pass", "pwd", "auth", "cred", "session", "cookie", "dsn"];

fn redact_argv(argv: &[String]) -> Vec<String> {
    argv.iter().map(|a| redact_arg(a)).collect()
}

fn redact_arg(arg: &str) -> String {
    // URL 里的 user:pass@host
    if let Some(scheme_end) = arg.find("://") {
        let rest = &arg[scheme_end + 3..];
        if let Some(at) = rest.find('@')
            && rest[..at].contains(':')
        {
            return format!("{}://***@{}", &arg[..scheme_end], &rest[at + 1..]);
        }
    }
    // --flag=value
    if let Some((flag, _)) = arg.split_once('=') {
        let lower = flag.to_ascii_lowercase();
        if SECRET_HINTS.iter().any(|h| lower.contains(h)) {
            return format!("{flag}=***");
        }
    }
    arg.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn framework_matches_on_basename() {
        let argv = args(["node", "/p/node_modules/.bin/vite", "--host"].as_slice());
        assert_eq!(match_framework("node", &argv), Some(("vite", "Vite")));
    }

    #[test]
    fn framework_matches_native_binary_by_exe() {
        // hugo / air 这类原生二进制,名字只在 exe 和 argv[0],不比 exe 就永远认不出
        let argv = args(["/opt/homebrew/bin/hugo", "server", "-D"].as_slice());
        assert_eq!(match_framework("hugo", &argv).map(|(_, l)| l), Some("Hugo"));
    }

    #[test]
    fn framework_ignores_bare_interpreter() {
        let argv = args(["node", "--inspect"].as_slice());
        assert_eq!(match_framework("node", &argv), None);
    }

    #[test]
    fn python_module_form_matches() {
        let argv = args(["python3", "-m", "http.server", "3009"].as_slice());
        assert_eq!(match_framework("python3", &argv).map(|(_, l)| l), Some("python http.server"));
    }

    #[test]
    fn dotted_module_matches_by_head() {
        // python -m vllm.entrypoints.openai.api_server
        let argv = args(["python3", "-m", "vllm.entrypoints.openai.api_server"].as_slice());
        assert_eq!(match_service("python3", &argv).map(|(_, l, _)| l), Some("vLLM"));
    }

    #[test]
    fn service_matches_by_exe() {
        assert_eq!(match_service("redis-server", &[]).map(|(_, l, _)| l), Some("Redis"));
        assert_eq!(match_service("postgres", &[]).map(|(_, _, k)| k), Some(Kind::Database));
    }

    #[test]
    fn entry_label_uses_script_path() {
        let argv = args(["bun", "--watch", "server/index.ts"].as_slice());
        assert_eq!(entry_label("bun", &argv).as_deref(), Some("bun server/index.ts"));
    }

    #[test]
    fn entry_label_trims_long_paths() {
        let argv = args(["python3", "/a/b/c/api/main.py"].as_slice());
        assert_eq!(entry_label("python3", &argv).as_deref(), Some("python3 api/main.py"));
    }

    #[test]
    fn entry_label_skips_flags() {
        let argv = args(["node", "--inspect", "--port=3000"].as_slice());
        assert_eq!(entry_label("node", &argv), None);
    }

    #[test]
    fn redacts_secrets() {
        assert_eq!(redact_arg("--api-key=abc123"), "--api-key=***");
        assert_eq!(redact_arg("--port=3000"), "--port=3000");
        assert_eq!(
            redact_arg("postgres://bob:hunter2@localhost/db"),
            "postgres://***@localhost/db"
        );
        assert_eq!(redact_arg("https://example.com/x"), "https://example.com/x");
    }
}
