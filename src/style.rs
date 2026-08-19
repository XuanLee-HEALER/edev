//! 极简 ANSI 着色。全局开关一次决定,渲染处零分支成本。

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR: AtomicBool = AtomicBool::new(false);

pub fn set_enabled(on: bool) {
    COLOR.store(on, Ordering::Relaxed);
}

#[must_use]
pub fn enabled() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// stdout 是终端且未设 `NO_COLOR` 时才上色。
#[must_use]
pub fn auto_detect() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    // SAFETY: isatty 只读 fd 状态,无副作用。
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

#[derive(Debug)]
pub struct Styled<'a, T: ?Sized>(&'a T, &'static str);

impl<T: fmt::Display + ?Sized> fmt::Display for Styled<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if enabled() { write!(f, "\x1b[{}m{}\x1b[0m", self.1, self.0) } else { self.0.fmt(f) }
    }
}

pub trait Paint {
    fn bold(&self) -> Styled<'_, Self>;
    /// 次要信息。用青色而不是灰色 —— ANSI 90 在浅色背景下几乎不可读。
    fn hint(&self) -> Styled<'_, Self>;
    fn red(&self) -> Styled<'_, Self>;
    fn green(&self) -> Styled<'_, Self>;
    fn yellow(&self) -> Styled<'_, Self>;
}

impl<T: fmt::Display + ?Sized> Paint for T {
    fn bold(&self) -> Styled<'_, Self> {
        Styled(self, "1")
    }
    fn hint(&self) -> Styled<'_, Self> {
        Styled(self, "36")
    }
    fn red(&self) -> Styled<'_, Self> {
        Styled(self, "31")
    }
    fn green(&self) -> Styled<'_, Self> {
        Styled(self, "32")
    }
    fn yellow(&self) -> Styled<'_, Self> {
        Styled(self, "33")
    }
}
