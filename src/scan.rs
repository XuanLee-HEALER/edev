//! 扫描聚合层:把平台后端吐出的裸 socket 拼成可读的 [`Entry`],并给每条做判定。

use crate::classify;
use crate::classify::Kind;
use crate::model::{ConnStats, Entry, ParentInfo, ProcInfo, Proto, Role, ScanStats, Sock};
use crate::platform::{self, ProcArgs};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

/// (pid, 端口) -> (协议集合, 绑定地址集合)
type ListenMap = FxHashMap<(i32, u16), (FxHashSet<Proto>, FxHashSet<IpAddr>)>;

#[derive(Debug, Clone)]
pub struct Filter {
    /// 端口白名单;`None` = 全 65535 端口。
    ///
    /// 全端口扫描本来就只要 2~4 ms,拿端口白名单当预过滤器只会漏掉 3800 这种
    /// 自定义端口 —— 真正的筛子是 [`crate::classify`],不是端口号。
    pub ranges: Option<Vec<(u16, u16)>>,
    /// 是否把 UDP 也算进来。
    pub udp: bool,
}

impl Filter {
    fn accepts(&self, s: &Sock) -> bool {
        if s.proto.is_udp() && !self.udp {
            return false;
        }
        self.ranges
            .as_ref()
            .is_none_or(|rs| rs.iter().any(|&(lo, hi)| s.port >= lo && s.port <= hi))
    }
}

/// 一个进程的额外证据,分类要用。
#[derive(Debug, Default)]
struct Extra {
    args: Option<ProcArgs>,
    cwd: Option<PathBuf>,
}

/// 跑一次完整扫描。`sample_ms > 0` 时额外做一轮 CPU 采样算瞬时占用。
pub fn collect(filter: &Filter, sample_ms: u64) -> (Vec<Entry>, ScanStats) {
    let (socks, stats) = platform::scan();

    // (pid, port) -> 协议 / 地址集合
    let mut grouped: ListenMap = FxHashMap::default();
    for s in socks.iter().filter(|s| s.role == Role::Listen && filter.accepts(s)) {
        let slot = grouped.entry((s.pid, s.port)).or_default();
        slot.0.insert(s.proto);
        slot.1.insert(s.addr);
    }
    if grouped.is_empty() {
        return (Vec::new(), stats);
    }

    let conns = count_conns(&socks);

    let pids: Vec<i32> =
        grouped.keys().map(|&(pid, _)| pid).collect::<FxHashSet<_>>().into_iter().collect();
    let mut infos: FxHashMap<i32, ProcInfo> =
        pids.par_iter().filter_map(|&p| platform::proc_info(p).map(|i| (p, i))).collect();

    if sample_ms > 0 {
        apply_cpu_sample(&mut infos, sample_ms);
    }

    // 分类证据:命令行 + 工作目录。只对候选进程取,每个两次系统调用。
    let extras: FxHashMap<i32, Extra> = pids
        .par_iter()
        .map(|&p| (p, Extra { args: platform::cmdline(p), cwd: platform::cwd(p) }))
        .collect();

    // 父进程信息独立取一遍,ppid 可能不在监听集合里。
    let parent_pids: Vec<i32> = infos
        .values()
        .map(|i| i.ppid)
        .filter(|&p| p > 0)
        .collect::<FxHashSet<_>>()
        .into_iter()
        .collect();
    let parents: FxHashMap<i32, ParentInfo> = parent_pids
        .par_iter()
        .filter_map(|&p| {
            platform::brief(p).map(|(name, exe)| (p, ParentInfo { pid: p, name, exe }))
        })
        .collect();

    let guard = SelfGuard::new();

    let mut entries: Vec<Entry> = grouped
        .into_iter()
        .filter_map(|((pid, port), (protos, addrs))| {
            let info = infos.get(&pid)?.clone();
            let protection = guard.protection(&info);
            let mut protos: Vec<_> = protos.into_iter().collect();
            protos.sort_unstable();
            let mut addrs: Vec<_> = addrs.into_iter().collect();
            addrs.sort_unstable();

            let parent = parents.get(&info.ppid).cloned();
            let extra = extras.get(&pid);
            let conns = conns.get(&(pid, port)).copied().unwrap_or_default();
            let verdict = classify::classify(&classify::Input {
                proc: &info,
                parent_name: parent.as_ref().map(|p| p.name.as_str()),
                args: extra.and_then(|e| e.args.as_ref()),
                cwd: extra.and_then(|e| e.cwd.as_deref()),
                conns: &conns,
                loopback_only: !addrs.is_empty() && addrs.iter().all(IpAddr::is_loopback),
                system: system_component(&info),
            });

            Some(Entry { port, protos, addrs, verdict, conns, protection, parent, proc: info })
        })
        .collect();

    entries.sort_unstable_by(|a, b| a.port.cmp(&b.port).then(a.proc.pid.cmp(&b.proc.pid)));
    (entries, stats)
}

/// 数每个监听端口上的 ESTABLISHED 连接,区分本机来的和外部来的。
///
/// 后端已经保证只返回「本进程同时也在监听该端口」的 ESTABLISHED,这里直接计数。
fn count_conns(socks: &[Sock]) -> FxHashMap<(i32, u16), ConnStats> {
    let mut out: FxHashMap<(i32, u16), ConnStats> = FxHashMap::default();
    for s in socks.iter().filter(|s| s.role == Role::Established) {
        let slot = out.entry((s.pid, s.port)).or_default();
        slot.total += 1;
        if !s.peer.is_some_and(|p| p.is_loopback()) {
            slot.external += 1;
        }
    }
    out
}

/// 显示 / 清理的取值范围。两条路径共用,免得各写一份然后漂移。
#[derive(Debug, Clone, Copy, Default)]
pub struct Scope {
    /// 什么都要,含系统组件。
    pub all: bool,
    /// 只要 dev server。
    pub dev_only: bool,
    /// 把判不出来的也算进来。
    pub include_unknown: bool,
}

impl Scope {
    /// 这个判定结果在不在范围内。
    #[must_use]
    pub const fn admits(self, kind: Kind) -> bool {
        if self.dev_only {
            return matches!(kind, Kind::DevServer);
        }
        if self.all {
            return true;
        }
        kind.shown_by_default() || (self.include_unknown && matches!(kind, Kind::Unknown))
    }
}

/// 两次读累计 CPU 时间,算采样窗口内的瞬时占用。
fn apply_cpu_sample(infos: &mut FxHashMap<i32, ProcInfo>, sample_ms: u64) {
    let before: Vec<(i32, u64)> =
        infos.keys().filter_map(|&p| platform::cpu_time_ns(p).map(|n| (p, n))).collect();
    thread::sleep(Duration::from_millis(sample_ms));
    let window_ns = (sample_ms as f64) * 1e6;
    for (pid, t0) in before {
        if let (Some(t1), Some(info)) = (platform::cpu_time_ns(pid), infos.get_mut(&pid)) {
            info.cpu_now_pct = Some(t1.saturating_sub(t0) as f64 / window_ns * 100.0);
        }
    }
}

/// 是不是系统自带的组件 —— 这是**身份**判定,和能不能杀是两回事。
///
/// 返回 `Some(理由)`。理由字符串同时喂给 [`crate::classify`] 当判定依据。
#[must_use]
pub fn system_component(info: &ProcInfo) -> Option<&'static str> {
    if info.pid <= 1 {
        return Some("init 进程");
    }
    if platform::SYSTEM_SERVICE_NAMES.contains(&info.name.as_str()) {
        return Some("已知系统服务");
    }
    let system_path =
        info.exe.as_deref().map(Path::to_string_lossy).is_some_and(|p| {
            platform::SYSTEM_PATH_PREFIXES.iter().any(|prefix| p.starts_with(prefix))
        });
    if info.uid == 0 && system_path {
        return Some("root 运行的系统组件");
    }
    None
}

/// 自保护:自己和自己的祖先不许被误杀,否则会顺手杀掉自己的终端。
#[derive(Debug)]
pub struct SelfGuard {
    lineage: FxHashSet<i32>,
}

impl SelfGuard {
    #[must_use]
    pub fn new() -> Self {
        let mut lineage = FxHashSet::default();
        let mut pid = platform::self_pid();
        // 沿 ppid 一路向上,顺手防环。
        for _ in 0..64 {
            if pid <= 0 || !lineage.insert(pid) {
                break;
            }
            match platform::ppid(pid) {
                Some(parent) => pid = parent,
                None => break,
            }
        }
        Self { lineage }
    }

    /// 能不能动。返回 `Some(理由)` 表示不许动。
    ///
    /// 这是**策略**,比 [`system_component`] 的身份判定多一条自保护 —— 一个普通
    /// 的 shell 是我的祖先时不许杀,但它并不因此就变成「系统组件」。
    #[must_use]
    pub fn protection(&self, info: &ProcInfo) -> Option<&'static str> {
        if self.lineage.contains(&info.pid) {
            return Some("edev 自身或其祖先进程");
        }
        system_component(info)
    }
}

impl Default for SelfGuard {
    fn default() -> Self {
        Self::new()
    }
}
