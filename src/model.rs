//! 核心数据结构。数据结构定下来,算法就显然了。

use serde::Serialize;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Proto {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tcp6 => "tcp6",
            Self::Udp => "udp",
            Self::Udp6 => "udp6",
        }
    }

    #[must_use]
    pub const fn is_udp(self) -> bool {
        matches!(self, Self::Udp | Self::Udp6)
    }
}

/// socket 的角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// TCP LISTEN,或未连接的 UDP。
    Listen,
    /// TCP ESTABLISHED —— 拿它数活跃连接。
    Established,
}

/// 单个 socket,扫描阶段的原始产物。
#[derive(Debug, Clone, Copy)]
pub struct Sock {
    pub pid: i32,
    pub port: u16,
    pub proto: Proto,
    pub addr: IpAddr,
    pub role: Role,
    /// ESTABLISHED 时的对端地址。
    pub peer: Option<IpAddr>,
}

/// 进程画像。
#[derive(Debug, Clone, Serialize)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: i32,
    /// 可执行文件的文件名;路径读不到时回退到内核里的 `pbi_name` / `pbi_comm`。
    pub name: String,
    /// 可执行文件全路径。
    pub exe: Option<PathBuf>,
    pub uid: u32,
    pub user: Option<String>,
    /// 启动时刻(Unix 秒)。
    pub start_epoch: u64,
    /// 已运行时长(秒)。
    pub uptime_secs: u64,
    /// 累计 CPU 时间(秒,user + system)。
    pub cpu_time_secs: f64,
    /// 生命周期平均 CPU 占用百分比。
    pub cpu_avg_pct: f64,
    /// 采样窗口内的瞬时 CPU 占用百分比(仅 `--sample` 时有值)。
    pub cpu_now_pct: Option<f64>,
    pub rss_bytes: u64,
    pub vsz_bytes: u64,
    pub threads: u32,
}

/// 某个 (pid, 端口) 上的活跃连接统计 —— 唯一零成本就能拿到的“流量特征”。
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ConnStats {
    pub total: u32,
    /// 对端是外部主机。剩下的就是本机来的,不再单存一份免得对不上。
    pub external: u32,
}

impl ConnStats {
    /// 对端在本机的连接数。
    #[must_use]
    pub const fn local(self) -> u32 {
        self.total.saturating_sub(self.external)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ParentInfo {
    pub pid: i32,
    pub name: String,
    pub exe: Option<PathBuf>,
}

/// 一条诊断结果:某进程在某端口上的监听。
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub port: u16,
    /// 同一 (pid, port) 上出现过的协议,已去重排序。
    pub protos: Vec<Proto>,
    /// 绑定地址,已去重排序。存 `IpAddr` 而不是 `String`,
    /// 免得回环 / 通配符的判断在各处各写一套字符串比较。
    pub addrs: Vec<IpAddr>,
    /// 综合命令行 / 工作目录 / 父进程 / 环境变量 / 连接情况得出的判定。
    pub verdict: crate::classify::Verdict,
    /// 这个端口上的活跃连接。
    pub conns: ConnStats,
    /// `clean` 为什么不能动它。有值就是绝对不动 —— edev 不是通用的杀进程工具,
    /// 系统组件和自身祖先没有任何开关可以放行。
    ///
    /// 注意这是**策略**,不等于 `verdict.kind == System` 那个**身份** ——
    /// 自己的祖先 shell 也受保护,但它不是系统组件。
    pub protection: Option<&'static str>,
    #[serde(flatten)]
    pub proc: ProcInfo,
    pub parent: Option<ParentInfo>,
}

/// 一次扫描的统计信息。
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ScanStats {
    /// 遍历到的进程数。
    pub pids_seen: usize,
    /// 因权限被拒的进程数(需要 sudo 才能看到)。
    pub pids_denied: usize,
    /// 扫描耗时(毫秒)。
    pub elapsed_ms: u128,
}
