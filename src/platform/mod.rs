//! 平台后端。
//!
//! 后端提供下面这些,其余逻辑全平台共用:
//!
//! * [`scan`] —— 枚举本机全部 socket:TCP LISTEN、TCP ESTABLISHED、未连接的 UDP;
//! * [`proc_info`] —— 按 pid 取进程画像(全路径 / 父进程 / 时长 / 资源);
//! * [`brief`] —— 只取名字和路径的轻量版,给父进程用;
//! * [`cmdline`] —— argv + envp,分类的主要证据;
//! * [`cwd`] —— 工作目录,分类的次要证据;
//! * [`cpu_time_ns`] —— 累计 CPU 时间,两次采样算瞬时占用;
//! * [`ppid`] / [`self_pid`] —— 走祖先链做自保护要用;
//! * [`SYSTEM_SERVICE_NAMES`] / [`SYSTEM_PATH_PREFIXES`] / [`SUPERVISOR_NAME`] ——
//!   认系统组件要用的名字和路径,各平台一份;
//! * [`local_time`] —— 时间格式化要调 libc,顺手也放后端。
//!
//! macOS 后端走 libproc + sysctl,不 fork `lsof`。

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{
    ProcArgs, SUPERVISOR_NAME, SYSTEM_PATH_PREFIXES, SYSTEM_SERVICE_NAMES, brief, cmdline,
    cpu_time_ns, cwd, local_time, ppid, proc_info, scan, self_pid,
};

#[cfg(not(target_os = "macos"))]
compile_error!(
    "edev 目前只实现了 macOS 后端。要加 Linux 支持,在 src/platform/ 下新增 linux.rs \
     实现 scan/proc_info/brief/cmdline/cwd/cpu_time_ns/ppid/self_pid/local_time \
     以及 SYSTEM_SERVICE_NAMES / SYSTEM_PATH_PREFIXES / SUPERVISOR_NAME 三个常量即可 \
     (Linux 上分别是 systemd 那套名字、/usr/lib/systemd 之类前缀、以及 \"systemd\") \
     (socket 读 /proc/net/tcp* 拿 inode 再扫 /proc/<pid>/fd 反查;argv 和 cwd 直接读 \
     /proc/<pid>/cmdline 和 /proc/<pid>/cwd)。"
);
