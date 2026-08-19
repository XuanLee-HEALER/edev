//! 命令行定义。

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "edev",
    version,
    about = "诊断并清理本机监听常见开发端口的服务",
    long_about = "扫描本机所有处于 LISTEN 的端口,匹配常见开发端口(Vite / Next / Postgres / Redis ...),\n\
                  给出进程全路径、运行时长、CPU 与内存占用、父进程,并支持定向或全量清理。\n\
                  直接读内核 libproc 接口,不 fork lsof。\n\n\
                  非本用户的进程需要 sudo 才可见。",
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,

    /// 不带子命令时等价于 `edev scan`
    #[command(flatten)]
    pub scan: ScanArgs,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// 扫描并展示监听中的开发端口(默认命令)
    Scan(ScanArgs),
    /// 清理占用端口的进程:定向或全部
    Clean(CleanArgs),
}

#[derive(Debug, Args, Clone)]
pub struct ScanArgs {
    /// 连系统组件和判不出来的一起列出来(默认只列 dev server / 数据库 / 基础设施 / 容器转发)
    #[arg(short, long)]
    pub all: bool,

    /// 只看这些端口,例:3000,8080,9000-9010(默认全端口扫描)
    #[arg(short, long, value_name = "SPEC")]
    pub ports: Option<String>,

    /// 只看判定为 dev server 的条目,过滤掉数据库、基础设施、系统组件
    #[arg(short = 'd', long)]
    pub dev_only: bool,

    /// 把判不出来的进程也列出来(仍不含系统组件)
    #[arg(long)]
    pub include_unknown: bool,

    /// 详细模式:进程全路径、父进程路径、虚存、线程数、判定依据
    #[arg(short, long)]
    pub long: bool,

    /// 也统计 UDP 监听
    #[arg(long)]
    pub udp: bool,

    /// 采样窗口毫秒数,给出瞬时 CPU 占用;0 表示只算生命周期均值
    #[arg(short, long, value_name = "MS", default_value_t = 0)]
    pub sample: u64,

    /// 输出 JSON
    #[arg(long)]
    pub json: bool,

    /// 关闭彩色输出
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Debug, Args, Clone)]
pub struct CleanArgs {
    /// 清理目标:端口 `3000`、端口区间 `9000-9010`、或进程 `pid:1234`。
    /// 不给目标且不加 --all 时进入交互选择。
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    /// 清理范围内的全部条目
    #[arg(short, long)]
    pub all: bool,

    /// 限定扫描范围,同 `scan --ports`
    #[arg(short, long, value_name = "SPEC")]
    pub ports: Option<String>,

    /// 把判不出来的进程也纳入 --all 的范围(默认只动 dev server / 数据库 / 基础设施 / 容器转发)
    #[arg(long)]
    pub include_unknown: bool,

    /// 也清理 UDP 监听者
    #[arg(long)]
    pub udp: bool,

    /// 只动判定为 dev server 的进程 —— 配 --all 用最顺手
    #[arg(short = 'd', long)]
    pub dev_only: bool,

    /// 跳过确认
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// 直接 SIGKILL,不给 SIGTERM 宽限
    #[arg(short, long)]
    pub force: bool,

    /// SIGTERM 后的宽限秒数
    #[arg(long, value_name = "SECS", default_value_t = 3)]
    pub grace: u64,

    /// 宽限期满也不升级到 SIGKILL
    #[arg(long)]
    pub no_escalate: bool,

    /// 只打印计划,不真的发信号
    #[arg(long)]
    pub dry_run: bool,

    /// 输出 JSON
    #[arg(long)]
    pub json: bool,

    /// 关闭彩色输出
    #[arg(long)]
    pub no_color: bool,
}

/// 解析 `--ports` 的值:`3000,8080,9000-9010`。
pub fn parse_port_spec(spec: &str) -> Result<Vec<(u16, u16)>, String> {
    let mut out = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u16 = lo.trim().parse().map_err(|_| format!("非法端口: {lo}"))?;
            let hi: u16 = hi.trim().parse().map_err(|_| format!("非法端口: {hi}"))?;
            if lo > hi {
                return Err(format!("端口区间反了: {part}"));
            }
            out.push((lo, hi));
        } else {
            let p: u16 = part.parse().map_err(|_| format!("非法端口: {part}"))?;
            out.push((p, p));
        }
    }
    if out.is_empty() { Err("端口列表为空".to_owned()) } else { Ok(out) }
}

/// `clean` 的目标表达式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Port(u16),
    Range(u16, u16),
    Pid(i32),
}

impl Target {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("pid:").or_else(|| s.strip_prefix('@')) {
            let pid: i32 = rest.parse().map_err(|_| format!("非法 pid: {rest}"))?;
            if pid <= 1 {
                return Err(format!("拒绝操作 pid {pid}"));
            }
            return Ok(Self::Pid(pid));
        }
        if let Some((lo, hi)) = s.split_once('-') {
            let lo: u16 = lo.trim().parse().map_err(|_| format!("非法端口: {lo}"))?;
            let hi: u16 = hi.trim().parse().map_err(|_| format!("非法端口: {hi}"))?;
            if lo > hi {
                return Err(format!("端口区间反了: {s}"));
            }
            return Ok(Self::Range(lo, hi));
        }
        s.parse::<u16>().map(Self::Port).map_err(|_| format!("无法识别的目标: {s}"))
    }

    #[must_use]
    pub const fn matches(self, port: u16, pid: i32) -> bool {
        match self {
            Self::Port(p) => p == port,
            Self::Range(lo, hi) => port >= lo && port <= hi,
            Self::Pid(p) => p == pid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing() {
        assert_eq!(Target::parse("3000").unwrap(), Target::Port(3000));
        assert_eq!(Target::parse("9000-9010").unwrap(), Target::Range(9000, 9010));
        assert_eq!(Target::parse("pid:42").unwrap(), Target::Pid(42));
        assert_eq!(Target::parse("@42").unwrap(), Target::Pid(42));
        assert!(Target::parse("pid:1").is_err());
        assert!(Target::parse("nope").is_err());
    }

    #[test]
    fn port_spec_parsing() {
        assert_eq!(parse_port_spec("3000,9000-9010").unwrap(), vec![(3000, 3000), (9000, 9010)]);
        assert!(parse_port_spec("9010-9000").is_err());
        assert!(parse_port_spec("abc").is_err());
    }

    #[test]
    fn target_matching() {
        assert!(Target::Range(9000, 9010).matches(9005, 1));
        assert!(!Target::Range(9000, 9010).matches(8999, 1));
        assert!(Target::Pid(7).matches(1, 7));
    }
}
