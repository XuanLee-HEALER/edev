//! 输出层:紧凑表格 / 详细块 / JSON。

use crate::classify::Kind;
use crate::model::{Entry, ScanStats};
use crate::style::Paint;
use serde::Serialize;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;

/// 紧凑表格的表头。
const HEAD: [&str; 10] =
    ["PORT", "PROTO", "ADDR", "PID", "PROCESS", "CPU", "MEM", "UPTIME", "CONN", "PARENT"];

/// 表格列宽按显示宽度算,CJK 记 2 格。
fn width(s: &str) -> usize {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            let wide = matches!(cp,
                0x1100..=0x115F | 0x2E80..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF
                | 0xFE30..=0xFE6F | 0xFF00..=0xFF60 | 0xFFE0..=0xFFE6 | 0x1F300..=0x1FAFF);
            usize::from(wide) + 1
        })
        .sum()
}

fn pad(s: &str, w: usize) -> String {
    let cur = width(s);
    if cur >= w { s.to_owned() } else { format!("{s}{}", " ".repeat(w - cur)) }
}

/// 从左侧截断,保留路径尾部这段更有信息量的部分。
fn trunc_left(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_owned();
    }
    let keep: String =
        s.chars().rev().take(max.saturating_sub(1)).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{keep}")
}

#[must_use]
pub fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", UNITS[i]) }
}

#[must_use]
pub fn human_dur(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60, secs % 60);
    if d > 0 {
        format!("{d}d{h}h")
    } else if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// 绑定地址的紧凑展示:通配符折成 `*`。
#[must_use]
pub fn addr_display(addrs: &[IpAddr]) -> String {
    if addrs.iter().any(IpAddr::is_unspecified) {
        return "*".to_owned();
    }
    addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

/// 表格里挂在每行下面的判定行。
fn annotation(e: &Entry) -> String {
    let v = &e.verdict;
    let mut note = String::from("    ↳ ");
    match &v.label {
        Some(l) => {
            let _ = write!(note, "{l} · {}({})", v.kind.as_str(), v.confidence.as_str());
        }
        None => {
            let _ = write!(note, "{}({})", v.kind.as_str(), v.confidence.as_str());
        }
    }
    if let Some(root) = &v.project {
        let _ = write!(note, "  {}", tildify(root));
    }
    if let Some(why) = e.protection {
        let _ = write!(note, "  [受保护: {why}]");
    }
    note
}

/// home 目录折成 `~`,路径短一截。
#[must_use]
pub fn tildify(p: &Path) -> String {
    std::env::var_os("HOME")
        .and_then(|h| p.strip_prefix(Path::new(&h)).ok().map(|r| format!("~/{}", r.display())))
        .unwrap_or_else(|| p.display().to_string())
}

/// `tcp/tcp6` 这样的协议串。
fn protos_of(e: &Entry) -> String {
    e.protos.iter().map(|p| p.as_str()).collect::<Vec<_>>().join("/")
}

fn cpu_of(e: &Entry) -> String {
    e.proc
        .cpu_now_pct
        .map_or_else(|| format!("{:.1}%~", e.proc.cpu_avg_pct), |now| format!("{now:.1}%"))
}

/// 紧凑表格。
pub fn table(entries: &[Entry], out: &mut impl Write) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let rows: Vec<[String; 10]> = entries
        .iter()
        .map(|e| {
            [
                e.port.to_string(),
                protos_of(e),
                addr_display(&e.addrs),
                e.proc.pid.to_string(),
                trunc_left(&e.proc.name, 24),
                cpu_of(e),
                human_bytes(e.proc.rss_bytes),
                human_dur(e.proc.uptime_secs),
                if e.conns.total == 0 { "-".to_owned() } else { e.conns.total.to_string() },
                e.parent.as_ref().map_or_else(
                    || format!("#{}", e.proc.ppid),
                    |p| format!("{} ({})", trunc_left(&p.name, 16), p.pid),
                ),
            ]
        })
        .collect();

    let mut w = HEAD.map(width);
    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            w[i] = w[i].max(width(cell));
        }
    }

    let head: String = HEAD.iter().enumerate().map(|(i, h)| pad(h, w[i] + 2)).collect::<String>();
    writeln!(out, "{}", head.trim_end().bold())?;

    for (e, r) in entries.iter().zip(&rows) {
        let mut line = String::new();
        for (i, cell) in r.iter().enumerate() {
            line.push_str(&pad(cell, w[i] + 2));
        }
        writeln!(out, "{}", line.trim_end())?;
        writeln!(out, "{}", annotation(e).hint())?;
    }
    Ok(())
}

/// 详细块:带全路径、父进程全路径、线程数、虚拟内存。
pub fn long(entries: &[Entry], out: &mut impl Write) -> io::Result<()> {
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        let protos = protos_of(e);
        let title = format!(":{}", e.port);
        write!(out, "{} {protos} {}", title.bold().green(), addr_display(&e.addrs))?;
        if let Some(l) = &e.verdict.label {
            write!(out, "  {}", format!("({l})").hint())?;
        }
        if let Some(why) = e.protection {
            write!(out, "  {}", format!("[受保护: {why}]").yellow())?;
        }
        writeln!(out)?;

        let p = &e.proc;
        writeln!(
            out,
            "  进程    {} (pid {})  用户 {}",
            p.name.bold(),
            p.pid,
            p.user.as_deref().unwrap_or("?")
        )?;
        writeln!(
            out,
            "  路径    {}",
            p.exe.as_ref().map_or_else(|| "<不可读>".to_owned(), |x| x.display().to_string())
        )?;
        match &e.parent {
            Some(par) => {
                writeln!(out, "  父进程  {} (pid {})", par.name, par.pid)?;
                if let Some(x) = &par.exe {
                    writeln!(out, "          {}", x.display().to_string().hint())?;
                }
            }
            None => writeln!(out, "  父进程  pid {}", p.ppid)?,
        }
        writeln!(
            out,
            "  时长    {}  (启动于 {})",
            human_dur(p.uptime_secs),
            crate::platform::local_time(p.start_epoch)
        )?;
        writeln!(
            out,
            "  资源    CPU {}  累计 {}  内存 {}  虚存 {}  线程 {}",
            cpu_of(e),
            human_dur(p.cpu_time_secs as u64),
            human_bytes(p.rss_bytes),
            human_bytes(p.vsz_bytes),
            p.threads
        )?;
        writeln!(
            out,
            "  连接    {} 条活跃(本机 {} / 外部 {})",
            e.conns.total,
            e.conns.local(),
            e.conns.external
        )?;
        write_verdict(e, out)?;
    }
    Ok(())
}

/// 详细模式里的判定与依据。
fn write_verdict(e: &Entry, out: &mut impl Write) -> io::Result<()> {
    let v = &e.verdict;
    let head = v
        .label
        .as_ref()
        .map_or_else(|| v.kind.as_str().to_owned(), |l| format!("{l} · {}", v.kind.as_str()));
    writeln!(
        out,
        "  判定    {}  {}",
        head.bold(),
        format!("(置信度 {}, 得分 {})", v.confidence.as_str(), v.score).hint()
    )?;
    if let Some(dir) = &v.cwd {
        writeln!(out, "  目录    {}", tildify(dir))?;
    }
    if !v.argv.is_empty() {
        writeln!(out, "  命令行  {}", trunc_left(&v.argv.join(" "), 160))?;
    }
    for (i, line) in v.evidence.iter().enumerate() {
        let tag = if i == 0 { "  依据    " } else { "          " };
        writeln!(out, "{tag}{line}")?;
    }
    Ok(())
}

#[derive(Serialize)]
struct JsonReport<'a> {
    stats: &'a ScanStats,
    count: usize,
    entries: &'a [Entry],
}

pub fn json(entries: &[Entry], stats: &ScanStats, out: &mut impl Write) -> io::Result<()> {
    let report = JsonReport { stats, count: entries.len(), entries };
    serde_json::to_writer_pretty(&mut *out, &report)?;
    writeln!(out)
}

/// 默认视图里被判定挡掉的条目数,按 [`Kind`] 分桶。
///
/// 按 `Kind::ALL` 索引而不是几个具名字段 —— 新增一个 `Kind` 时不会悄悄掉进
/// “其它”这种没信息量的桶里。
#[derive(Debug, Clone, Copy, Default)]
pub struct Hidden([usize; Kind::ALL.len()]);

impl Hidden {
    pub const fn add(&mut self, kind: Kind) {
        self.0[kind.index()] += 1;
    }

    #[must_use]
    pub fn total(self) -> usize {
        self.0.iter().sum()
    }

    /// `系统组件 3 · 未知 6`
    fn breakdown(self) -> String {
        Kind::ALL
            .iter()
            .zip(self.0)
            .filter(|(_, n)| *n > 0)
            .map(|(k, n)| format!("{} {n}", k.as_str()))
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// 扫描尾注:隐藏了多少、权限提示。
pub fn footer(
    stats: &ScanStats,
    shown: usize,
    hidden: Hidden,
    out: &mut impl Write,
) -> io::Result<()> {
    let mut note =
        format!("{shown} 条 / 扫描 {} 个进程 / {} ms", stats.pids_seen, stats.elapsed_ms);
    if hidden.total() > 0 {
        let _ = write!(note, " / 隐藏 {} 条({}),-a 全看", hidden.total(), hidden.breakdown());
    }
    if stats.pids_denied > 0 {
        let _ = write!(note, " / {} 个进程无权限查看(sudo edev 可看全)", stats.pids_denied);
    }
    writeln!(out, "{}", note.hint())
}
