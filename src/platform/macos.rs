//! macOS 后端:libproc + sysctl 直连内核,零子进程。
//!
//! socket 扫描:`pids_by_type` -> `proc_pidinfo(PROC_PIDTBSDINFO)` ->
//! `proc_pidinfo(PROC_PIDLISTFDS)` -> `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`,
//! pid 维度用 rayon 并行,LISTEN 和 ESTABLISHED 一趟全取。
//!
//! 分类证据:`KERN_PROCARGS2`(argv + envp)和 `proc_pidinfo(PROC_PIDVNODEPATHINFO)`(cwd),
//! 只对候选进程取,不进全量扫描路径。
//!
//! unsafe 用在:读 `SocketInfoProto` / `InSIAddr` 两个 C union,以及 `sysctl` /
//! `getpwuid` / `getpid` 三个 libc 调用。

use crate::model::{Proto, Role, ScanStats};
use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
use libproc::libproc::net_info::{InSockInfo, SocketFDInfo, SocketInfoKind, TcpSIState};
use libproc::libproc::proc_pid::{PIDInfo, PidInfoFlavor, listpidinfo, pidinfo, pidpath};
use libproc::libproc::task_info::TaskAllInfo;
use libproc::processes::{ProcFilter, pids_by_type};
use rayon::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// `insi_vflag` 位:地址是 IPv4。
const INI_IPV4: u8 = 0x1;

/// 扫描全部监听 socket,外加落在这些监听端口上的 ESTABLISHED 连接。
///
/// ESTABLISHED 只保留「本进程同时也在监听该端口」的那些 —— 浏览器那几百条出站
/// 连接对调用方毫无用处,在这里就丢掉,不必带到聚合层再过滤一遍。
///
/// 拿不到信息的进程(非本用户且未提权)计入 [`ScanStats::pids_denied`]。
#[must_use]
pub fn scan() -> (Vec<crate::model::Sock>, ScanStats) {
    let started = Instant::now();
    let pids = pids_by_type(ProcFilter::All).unwrap_or_default();
    let denied = AtomicUsize::new(0);

    let socks: Vec<crate::model::Sock> =
        pids.par_iter().flat_map_iter(|&pid| scan_pid(pid as i32, &denied)).collect();

    let stats = ScanStats {
        pids_seen: pids.len(),
        pids_denied: denied.load(Ordering::Relaxed),
        elapsed_ms: started.elapsed().as_millis(),
    };
    (socks, stats)
}

/// 单进程的 socket 扫描。返回空 Vec 不分配。
fn scan_pid(pid: i32, denied: &AtomicUsize) -> Vec<crate::model::Sock> {
    let Ok(bsd) = pidinfo::<BSDInfo>(pid, 0) else {
        denied.fetch_add(1, Ordering::Relaxed);
        return Vec::new();
    };
    // pbi_nfiles 是调用瞬间的开表数,留点余量防止截断。
    let cap = (bsd.pbi_nfiles as usize).max(64) + 64;
    let Ok(fds) = listpidinfo::<ListFDs>(pid, cap) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for fd in fds {
        if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
            continue;
        }
        let Ok(sock) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) else {
            continue;
        };
        match SocketInfoKind::from(sock.psi.soi_kind) {
            SocketInfoKind::Tcp => {
                // SAFETY: soi_kind == Tcp 保证这个 union 分支有效。
                let tcp = unsafe { sock.psi.soi_proto.pri_tcp };
                let role = match TcpSIState::from(tcp.tcpsi_state) {
                    TcpSIState::Listen => Role::Listen,
                    TcpSIState::Established => Role::Established,
                    _ => continue,
                };
                if let Some(l) = to_sock(pid, &tcp.tcpsi_ini, false, role) {
                    out.push(l);
                }
            }
            SocketInfoKind::In => {
                if sock.psi.soi_protocol != libc::IPPROTO_UDP {
                    continue;
                }
                // SAFETY: soi_kind == In 保证这个 union 分支有效。
                let inp = unsafe { sock.psi.soi_proto.pri_in };
                // 已连接的 UDP socket 有对端端口,不算“在监听”。
                if ntohs(inp.insi_fport) != 0 {
                    continue;
                }
                if let Some(l) = to_sock(pid, &inp, true, Role::Listen) {
                    out.push(l);
                }
            }
            _ => {}
        }
    }
    retain_own_listen_ports(&mut out);
    out
}

/// 丢掉本进程并没有在监听的那些端口上的 ESTABLISHED 连接。
fn retain_own_listen_ports(socks: &mut Vec<crate::model::Sock>) {
    if !socks.iter().any(|s| s.role == Role::Established) {
        return;
    }
    // 单进程的监听端口至多个位数,线性查找比建哈希快。
    let listening: Vec<u16> =
        socks.iter().filter(|s| s.role == Role::Listen).map(|s| s.port).collect();
    socks.retain(|s| s.role == Role::Listen || listening.contains(&s.port));
}

/// 网络字节序的端口字段转主机序。
const fn ntohs(port: libc::c_int) -> u16 {
    u16::from_be(port as u16)
}

fn to_sock(pid: i32, ini: &InSockInfo, udp: bool, role: Role) -> Option<crate::model::Sock> {
    let port = ntohs(ini.insi_lport);
    if port == 0 {
        return None;
    }
    let is_v4 = ini.insi_vflag & INI_IPV4 != 0;
    let addr = ini_addr(ini, is_v4, false);
    let peer = (role == Role::Established).then(|| ini_addr(ini, is_v4, true));
    let proto = match (udp, is_v4) {
        (false, true) => Proto::Tcp,
        (false, false) => Proto::Tcp6,
        (true, true) => Proto::Udp,
        (true, false) => Proto::Udp6,
    };
    Some(crate::model::Sock { pid, port, proto, addr, role, peer })
}

/// 从 union 里取本地或对端地址。
fn ini_addr(ini: &InSockInfo, is_v4: bool, foreign: bool) -> IpAddr {
    let slot = if foreign { &ini.insi_faddr } else { &ini.insi_laddr };
    if is_v4 {
        // SAFETY: insi_vflag 标了 IPv4,读 ina_46 分支有效。
        let raw = unsafe { slot.ina_46.i46a_addr4.s_addr };
        IpAddr::V4(Ipv4Addr::from(u32::from_be(raw)))
    } else {
        // SAFETY: 非 IPv4 即 IPv6,读 ina_6 分支有效。
        let raw = unsafe { slot.ina_6.s6_addr };
        IpAddr::V6(Ipv6Addr::from(raw))
    }
}

/// 只取父进程展示需要的两样东西,省掉 `TaskAllInfo` 和用户名解析。
#[must_use]
pub fn brief(pid: i32) -> Option<(String, Option<PathBuf>)> {
    let bsd = pidinfo::<BSDInfo>(pid, 0).ok()?;
    let exe = pidpath(pid).ok().map(PathBuf::from);
    Some((display_name(pid, exe.as_deref(), &bsd), exe))
}

/// 优先用可执行文件名,拿不到再退回内核里的 `pbi_name` / `pbi_comm`。
fn display_name(pid: i32, exe: Option<&std::path::Path>, bsd: &BSDInfo) -> String {
    exe.and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .or_else(|| cstr_field(&bsd.pbi_name))
        .or_else(|| cstr_field(&bsd.pbi_comm))
        .unwrap_or_else(|| format!("pid {pid}"))
}

/// 进程画像。`cpu_now_pct` 留空,由调用方决定是否二次采样。
#[must_use]
pub fn proc_info(pid: i32) -> Option<crate::model::ProcInfo> {
    let all = pidinfo::<TaskAllInfo>(pid, 0).ok()?;
    let exe = pidpath(pid).ok().map(PathBuf::from);
    let name = display_name(pid, exe.as_deref(), &all.pbsd);

    let start_epoch = all.pbsd.pbi_start_tvsec;
    let uptime_secs = now_epoch().saturating_sub(start_epoch);
    let cpu_time_secs = (all.ptinfo.pti_total_user + all.ptinfo.pti_total_system) as f64 / 1e9;
    let cpu_avg_pct =
        if uptime_secs == 0 { 0.0 } else { cpu_time_secs / uptime_secs as f64 * 100.0 };

    Some(crate::model::ProcInfo {
        pid,
        ppid: all.pbsd.pbi_ppid as i32,
        name,
        exe,
        uid: all.pbsd.pbi_uid,
        user: username(all.pbsd.pbi_uid),
        start_epoch,
        uptime_secs,
        cpu_time_secs,
        cpu_avg_pct,
        cpu_now_pct: None,
        rss_bytes: all.ptinfo.pti_resident_size,
        vsz_bytes: all.ptinfo.pti_virtual_size,
        threads: all.ptinfo.pti_threadnum as u32,
    })
}

/// 只取父进程 pid。走祖先链时用它,别拿 `proc_info` —— 那还要 `pidpath` 和用户名解析。
#[must_use]
pub fn ppid(pid: i32) -> Option<i32> {
    pidinfo::<BSDInfo>(pid, 0).ok().map(|b| b.pbi_ppid as i32)
}

/// 累计 CPU 时间(纳秒),用于采样算瞬时占用。
#[must_use]
pub fn cpu_time_ns(pid: i32) -> Option<u64> {
    let all = pidinfo::<TaskAllInfo>(pid, 0).ok()?;
    Some(all.ptinfo.pti_total_user + all.ptinfo.pti_total_system)
}

#[must_use]
pub fn self_pid() -> i32 {
    // SAFETY: getpid 无参数、无失败路径。
    unsafe { libc::getpid() }
}

/// uid -> 用户名的进程内缓存。条目数等于登录用户数,线性查找比哈希更快。
type UserCache = RwLock<Vec<(u32, Option<String>)>>;

/// uid -> 用户名,带进程内缓存。
///
/// `getpwuid` 在 macOS 上可能走 opendirectoryd 的 IPC,冷调用几百毫秒起步,
/// 并行扫描时每个进程各来一次会直接主导总耗时。
#[must_use]
pub fn username(uid: u32) -> Option<String> {
    static CACHE: OnceLock<UserCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(Vec::new()));
    if let Ok(g) = cache.read()
        && let Some((_, name)) = g.iter().find(|(u, _)| *u == uid)
    {
        return name.clone();
    }
    let looked_up = lookup_user(uid);
    if let Ok(mut g) = cache.write()
        && !g.iter().any(|(u, _)| *u == uid)
    {
        g.push((uid, looked_up.clone()));
    }
    looked_up
}

fn lookup_user(uid: u32) -> Option<String> {
    // SAFETY: getpwuid 返回静态缓冲区指针;这里立刻拷成 String,不跨调用持有。
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_name.is_null() {
            return None;
        }
        Some(std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// 把 bindgen 出来的定长 C 字符数组转成 String。
fn cstr_field(buf: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    if bytes.is_empty() { None } else { String::from_utf8(bytes).ok() }
}

// ---------------------------------------------------------------------------
// 分类用的额外证据:命令行 / 环境变量 / 工作目录
// ---------------------------------------------------------------------------

/// 进程的启动现场。
///
/// `env` 里可能有密钥,调用方只允许从中提取判定信号,不得原样保存或打印。
#[derive(Debug, Clone, Default)]
pub struct ProcArgs {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// 读 `KERN_PROCARGS2`。非本用户的进程会失败,返回 `None`。
#[must_use]
pub fn cmdline(pid: i32) -> Option<ProcArgs> {
    // 绝大多数命令行远小于 16 KiB,先试小的,不够再退回 ARGMAX。
    let buf = sysctl_procargs(pid, 16 * 1024)
        .or_else(|| sysctl_procargs(pid, argmax().unwrap_or(1 << 20)))?;
    parse_procargs(&buf)
}

fn argmax() -> Option<usize> {
    static ARGMAX: OnceLock<Option<usize>> = OnceLock::new();
    *ARGMAX.get_or_init(|| {
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>();
        // SAFETY: mib/value/len 都是本地变量,长度与类型匹配。
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                (&raw mut value).cast(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0 && value > 0).then_some(value as usize)
    })
}

fn sysctl_procargs(pid: i32, cap: usize) -> Option<Vec<u8>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut buf = vec![0u8; cap];
    let mut len = cap;
    // SAFETY: buf 至少有 len 字节;sysctl 回写实际长度到 len。
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len < std::mem::size_of::<libc::c_int>() {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

/// `KERN_PROCARGS2` 的布局:argc(4B) | `exec_path`\0 | 对齐 \0 | argv... | env...
fn parse_procargs(buf: &[u8]) -> Option<ProcArgs> {
    let count = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    if count < 0 {
        return None;
    }
    let mut rest = &buf[4..];

    // 跳过 exec_path 及其后面的对齐填充。
    let end = rest.iter().position(|&b| b == 0)?;
    rest = &rest[end..];
    let pad = rest.iter().position(|&b| b != 0).unwrap_or(rest.len());
    rest = &rest[pad..];

    let mut chunks = rest.split(|&b| b == 0).map(String::from_utf8_lossy);
    let argv: Vec<String> =
        chunks.by_ref().take(count as usize).map(std::borrow::Cow::into_owned).collect();
    let env = chunks
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect();
    Some(ProcArgs { argv, env })
}

const MAXPATHLEN: usize = 1024;

/// `struct vnode_info` —— 字段名必须照抄 xnu 头文件,布局才对得上。
#[repr(C)]
#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct VnodeInfo {
    vi_stat: libproc::libproc::net_info::VInfoStat,
    vi_type: libc::c_int,
    vi_pad: libc::c_int,
    vi_fsid: [i32; 2],
}

/// `struct vnode_info_path`
#[repr(C)]
struct VnodeInfoPath {
    vip_vi: VnodeInfo,
    vip_path: [libc::c_char; MAXPATHLEN],
}

impl Default for VnodeInfoPath {
    fn default() -> Self {
        Self { vip_vi: VnodeInfo::default(), vip_path: [0; MAXPATHLEN] }
    }
}

/// `struct proc_vnodepathinfo` —— libproc crate 没有导出,自己按 xnu 头文件排布。
#[repr(C)]
#[derive(Default)]
struct ProcVnodePathInfo {
    pvi_cdir: VnodeInfoPath,
    pvi_rdir: VnodeInfoPath,
}

impl PIDInfo for ProcVnodePathInfo {
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::VNodePathInfo
    }
}

/// 进程的当前工作目录。dev server 通常跑在项目目录里,守护进程通常在 `/`。
#[must_use]
pub fn cwd(pid: i32) -> Option<PathBuf> {
    let info = pidinfo::<ProcVnodePathInfo>(pid, 0).ok()?;
    let path = cstr_field(&info.pvi_cdir.vip_path)?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

// ---------------------------------------------------------------------------
// 平台常量:下面这些名字、路径、时间格式化都是 macOS 专有的,不能长在共享层
// ---------------------------------------------------------------------------

/// 按名字认的常驻系统服务。
///
/// 不含 `launchd` / `kernel_task` —— 它们是 pid 1 和 pid 0,通用的 `pid <= 1`
/// 规则先一步覆盖了,列在这里是死数据。
pub static SYSTEM_SERVICE_NAMES: &[&str] = &[
    "ControlCenter",
    "sharingd",
    "rapportd",
    "mDNSResponder",
    "remoted",
    "AirPlayXPCHelper",
    "netbiosd",
    "identityservicesd",
    "sshd",
    "sshd-keygen-wrapper",
    "cupsd",
    "coreaudiod",
    "WindowServer",
    "loginwindow",
];

/// 系统组件的安装路径前缀,配合 uid 0 一起判定。
pub static SYSTEM_PATH_PREFIXES: &[&str] =
    &["/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/usr/bin/", "/Library/Apple/"];

/// 服务托管进程的名字。父进程是它 = 开机自启的常驻服务,不是手动起的 dev server。
pub const SUPERVISOR_NAME: &str = "launchd";

/// Unix 秒转本地时间字符串。放在后端是因为要调 libc。
#[must_use]
pub fn local_time(epoch: u64) -> String {
    // SAFETY: localtime_r 写入我们自己栈上的 tm,指针有效且不共享。
    let tm = unsafe {
        let t = epoch as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&raw const t, &raw mut tm).is_null() {
            return epoch.to_string();
        }
        tm
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_own_cmdline() {
        let args = cmdline(self_pid()).expect("自己的 KERN_PROCARGS2 一定读得到");
        assert!(!args.argv.is_empty(), "argv 不该为空");
        assert!(args.env.iter().any(|(k, _)| k == "PATH"), "env 里应该有 PATH");
    }

    #[test]
    fn reads_own_cwd() {
        let got = cwd(self_pid()).expect("自己的 cwd 一定读得到");
        let want = std::env::current_dir().unwrap();
        assert_eq!(got.canonicalize().ok(), want.canonicalize().ok());
    }

    #[test]
    fn reads_own_exe_path() {
        let info = proc_info(self_pid()).expect("自己的进程信息一定读得到");
        // 测试时二进制名是 edev-<hash>,只断言前缀。
        let name = info.exe.and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()));
        assert!(name.is_some_and(|n| n.starts_with("edev")), "exe 文件名应以 edev 开头");
    }
}
