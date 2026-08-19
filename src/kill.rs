//! 进程清理:SIGTERM 宽限,超时再 SIGKILL。

use serde::Serialize;
use std::thread;
use std::time::{Duration, Instant};

/// SIGKILL 之后等内核回收的上限。到点没等到也照样报「已强杀」——
/// 信号已经投递,剩下的是内核的事。
const REAP_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy)]
pub struct KillOpts {
    /// SIGTERM 后的宽限期。
    pub grace: Duration,
    /// 直接上 SIGKILL,不给宽限。
    pub force: bool,
    /// 宽限期满后不升级到 SIGKILL。
    pub no_escalate: bool,
    /// 只打印不动手。
    pub dry_run: bool,
}

impl Default for KillOpts {
    fn default() -> Self {
        Self { grace: Duration::from_secs(3), force: false, no_escalate: false, dry_run: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "result", content = "detail")]
pub enum Outcome {
    /// SIGTERM 后自行退出。
    Terminated,
    /// 宽限期满,SIGKILL 收尾。
    Killed,
    /// 发信号时进程已经没了。
    AlreadyGone,
    /// 宽限期满仍在,且指定了不升级。
    StillAlive,
    /// 权限不足(通常需要 sudo)。
    Denied,
    /// 受保护,跳过。
    Skipped(String),
    /// dry-run 下的预演。
    Planned,
    Failed(String),
}

impl Outcome {
    #[must_use]
    pub const fn ok(&self) -> bool {
        matches!(self, Self::Terminated | Self::Killed | Self::AlreadyGone | Self::Planned)
    }

    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Terminated => "已终止 (SIGTERM)".to_owned(),
            Self::Killed => "已强杀 (SIGKILL)".to_owned(),
            Self::AlreadyGone => "已不存在".to_owned(),
            Self::StillAlive => "仍存活 (未升级 SIGKILL)".to_owned(),
            Self::Denied => "权限不足,试试 sudo".to_owned(),
            Self::Skipped(why) => format!("跳过: {why}"),
            Self::Planned => "待清理 (dry-run)".to_owned(),
            Self::Failed(e) => format!("失败: {e}"),
        }
    }
}

/// 进程是否还活着。
#[must_use]
pub fn alive(pid: i32) -> bool {
    // SAFETY: 信号 0 只做存在性与权限检查,不投递。
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    // EPERM 说明进程在、只是不归我们管。
    errno() == libc::EPERM
}

fn errno() -> i32 {
    // SAFETY: __error() 返回本线程 errno 的合法指针。
    unsafe { *libc::__error() }
}

fn send(pid: i32, sig: i32) -> Result<(), i32> {
    // SAFETY: 向具体 pid 投递信号;pid > 0 已由调用方保证,不会误伤进程组。
    if unsafe { libc::kill(pid, sig) } == 0 { Ok(()) } else { Err(errno()) }
}

/// 终止单个进程。
#[must_use]
pub fn terminate(pid: i32, opts: KillOpts) -> Outcome {
    if pid <= 1 {
        return Outcome::Skipped("非法 pid".to_owned());
    }
    if opts.dry_run {
        return if alive(pid) { Outcome::Planned } else { Outcome::AlreadyGone };
    }

    let first = if opts.force { libc::SIGKILL } else { libc::SIGTERM };
    if let Err(e) = send(pid, first) {
        return match e {
            libc::ESRCH => Outcome::AlreadyGone,
            libc::EPERM => Outcome::Denied,
            other => Outcome::Failed(format!("errno {other}")),
        };
    }
    if opts.force {
        wait_gone(pid, REAP_WAIT);
        return Outcome::Killed;
    }

    if wait_gone(pid, opts.grace) {
        return Outcome::Terminated;
    }
    if opts.no_escalate {
        return Outcome::StillAlive;
    }
    match send(pid, libc::SIGKILL) {
        Ok(()) | Err(libc::ESRCH) => {
            wait_gone(pid, REAP_WAIT);
            Outcome::Killed
        }
        Err(libc::EPERM) => Outcome::Denied,
        Err(other) => Outcome::Failed(format!("errno {other}")),
    }
}

/// 轮询等进程消失。真消失返回 `true`,到点还在返回 `false`。
fn wait_gone(pid: i32, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    let mut backoff = Duration::from_millis(10);
    loop {
        if !alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(100));
    }
}
