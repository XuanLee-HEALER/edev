//! edev —— 诊断并清理本机监听常见开发端口的服务。

mod classify;
mod cli;
mod kill;
mod model;
mod platform;
mod render;
mod scan;
mod style;

use clap::Parser;
use cli::{CleanArgs, Cli, Cmd, ScanArgs, Target};
use kill::{KillOpts, Outcome};
use model::Entry;
use render::Hidden;
use rustc_hash::FxHashMap;
use scan::{Filter, Scope};
use serde::Serialize;
use std::error::Error;
use std::io::{BufWriter, Write};
use std::process::ExitCode;
use std::time::Duration;
use style::Paint;

/// 子命令的返回类型。`Box<dyn Error>` 让 `io::Error` 和字符串错误都能直接 `?`。
type CmdResult = Result<ExitCode, Box<dyn Error>>;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        None => run_scan(&cli.scan),
        Some(Cmd::Scan(a)) => run_scan(&a),
        Some(Cmd::Clean(a)) => run_clean(&a),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {e}", "错误:".red().bold());
            ExitCode::from(2)
        }
    }
}

fn init_color(disabled: bool, json: bool) {
    style::set_enabled(!disabled && !json && style::auto_detect());
}

fn build_filter(spec: Option<&str>, udp: bool) -> Result<Filter, Box<dyn Error>> {
    let ranges = spec.map(cli::parse_port_spec).transpose()?;
    Ok(Filter { ranges, udp })
}

fn run_scan(a: &ScanArgs) -> CmdResult {
    init_color(a.no_color, a.json);
    let filter = build_filter(a.ports.as_deref(), a.udp)?;
    let (entries, stats) = scan::collect(&filter, a.sample);
    let scope = Scope { all: a.all, dev_only: a.dev_only, include_unknown: a.include_unknown };
    let (entries, hidden) = apply_scope(entries, scope);

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    if a.json {
        render::json(&entries, &stats, &mut out)?;
        return Ok(ExitCode::SUCCESS);
    }
    if entries.is_empty() {
        writeln!(out, "{}", "没有匹配的监听端口。".hint())?;
        render::footer(&stats, 0, hidden, &mut out)?;
        return Ok(ExitCode::SUCCESS);
    }
    if a.long {
        render::long(&entries, &mut out)?;
        writeln!(out)?;
    } else {
        render::table(&entries, &mut out)?;
    }
    render::footer(&stats, entries.len(), hidden, &mut out)?;
    Ok(ExitCode::SUCCESS)
}

#[derive(Serialize)]
struct CleanRecord<'a> {
    pid: i32,
    name: &'a str,
    ports: Vec<u16>,
    exe: Option<String>,
    #[serde(flatten)]
    outcome: Outcome,
}

fn run_clean(a: &CleanArgs) -> CmdResult {
    init_color(a.no_color, a.json);
    let filter = build_filter(a.ports.as_deref(), a.udp)?;
    let (mut entries, stats) = scan::collect(&filter, 0);
    // --all / 交互挑选只在范围内动手,避免误伤微信、编辑器这类判不出来的进程。
    // 显式点名端口或 pid 时不收范围 —— 指名道姓了就是要动它。
    if a.dev_only || a.targets.is_empty() {
        let scope = Scope { all: false, dev_only: a.dev_only, include_unknown: a.include_unknown };
        entries.retain(|e| scope.admits(e.verdict.kind));
    }

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    if entries.is_empty() {
        if a.json {
            writeln!(out, "[]")?;
        } else {
            writeln!(out, "{}", "没有匹配的监听端口,无事可做。".hint())?;
            render::footer(&stats, 0, Hidden::default(), &mut out)?;
        }
        return Ok(ExitCode::SUCCESS);
    }

    let selected = select_targets(a, &entries, &mut out)?;
    if selected.is_empty() {
        writeln!(out, "{}", "未选择任何目标。".hint())?;
        return Ok(ExitCode::SUCCESS);
    }

    let plan = merge_by_pid(selected);

    if !a.json {
        print_plan(&plan, &mut out)?;
    }

    let actionable = plan.iter().filter(|(e, _)| e.protection.is_none()).count();
    if actionable == 0 {
        writeln!(out, "{}", "全部目标都受保护,未执行任何操作。".yellow())?;
        return Ok(ExitCode::SUCCESS);
    }

    if !a.yes && !a.dry_run && !confirm(actionable, a.force, &mut out)? {
        writeln!(out, "{}", "已取消。".hint())?;
        return Ok(ExitCode::SUCCESS);
    }

    let opts = KillOpts {
        grace: Duration::from_secs(a.grace),
        force: a.force,
        no_escalate: a.no_escalate,
        dry_run: a.dry_run,
    };

    let mut records = Vec::with_capacity(plan.len());
    let mut failed = false;
    for (e, pts) in plan {
        let outcome = if e.protection.is_some() {
            Outcome::Skipped(e.protection.unwrap_or("受保护").to_owned())
        } else {
            kill::terminate(e.proc.pid, opts)
        };
        if !outcome.ok() && !matches!(outcome, Outcome::Skipped(_)) {
            failed = true;
        }
        records.push(CleanRecord {
            pid: e.proc.pid,
            name: &e.proc.name,
            ports: pts,
            exe: e.proc.exe.as_ref().map(|p| p.display().to_string()),
            outcome,
        });
    }

    if a.json {
        serde_json::to_writer_pretty(&mut out, &records)?;
        writeln!(out)?;
    } else {
        print_results(&records, &mut out)?;
    }

    Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// 按范围过滤,返回 (可见条目, 被挡掉的分桶统计)。
fn apply_scope(entries: Vec<Entry>, scope: Scope) -> (Vec<Entry>, Hidden) {
    let mut hidden = Hidden::default();
    let kept = entries
        .into_iter()
        .filter(|e| {
            let keep = scope.admits(e.verdict.kind);
            if !keep {
                hidden.add(e.verdict.kind);
            }
            keep
        })
        .collect();
    (kept, hidden)
}

/// 决定这次要动哪些条目:`--all` / 显式目标 / 交互挑选。
fn select_targets<'a>(
    a: &CleanArgs,
    entries: &'a [Entry],
    out: &mut impl Write,
) -> Result<Vec<&'a Entry>, Box<dyn Error>> {
    if a.all {
        return Ok(entries.iter().collect());
    }
    if a.targets.is_empty() {
        if a.json {
            return Err("clean 需要指定目标或 --all(JSON 模式不支持交互选择)".into());
        }
        return pick_interactive(entries, out);
    }
    let targets = a.targets.iter().map(|t| Target::parse(t)).collect::<Result<Vec<_>, _>>()?;
    let picked: Vec<&Entry> =
        entries.iter().filter(|e| targets.iter().any(|t| t.matches(e.port, e.proc.pid))).collect();
    if picked.is_empty() {
        return Err(format!("目标 {:?} 没有匹配到任何监听进程", a.targets).into());
    }
    Ok(picked)
}

/// 一个进程可能占多个端口,按 pid 合并,只发一次信号。
fn merge_by_pid(selected: Vec<&Entry>) -> Vec<(&Entry, Vec<u16>)> {
    let mut by_pid: FxHashMap<i32, (&Entry, Vec<u16>)> = FxHashMap::default();
    for e in selected {
        let slot = by_pid.entry(e.proc.pid).or_insert((e, Vec::new()));
        slot.1.push(e.port);
    }
    let mut plan: Vec<(&Entry, Vec<u16>)> = by_pid
        .into_values()
        .map(|(e, mut ports)| {
            ports.sort_unstable();
            ports.dedup();
            (e, ports)
        })
        .collect();
    plan.sort_unstable_by_key(|(e, _)| e.proc.pid);
    plan
}

/// `3000,8080` 这样的端口串。
fn ports_csv(ports: &[u16]) -> String {
    ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

fn print_plan(plan: &[(&Entry, Vec<u16>)], out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out, "{}", "将要清理:".bold())?;
    for (e, pts) in plan {
        let ports_s = ports_csv(pts);
        let line = format!(
            "  pid {:<7} {:<24} :{}  {}",
            e.proc.pid,
            e.proc.name,
            ports_s,
            e.proc.exe.as_ref().map_or_else(String::new, |p| p.display().to_string())
        );
        if e.protection.is_some() {
            writeln!(
                out,
                "{} {}",
                line.hint(),
                format!("[跳过: {}]", e.protection.unwrap_or("受保护")).yellow()
            )?;
        } else {
            writeln!(out, "{line}")?;
        }
    }
    out.flush()
}

fn print_results(records: &[CleanRecord<'_>], out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out)?;
    for r in records {
        let ports_s = ports_csv(&r.ports);
        let label = r.outcome.label();
        let head = format!("  pid {:<7} :{:<12} {:<24}", r.pid, ports_s, r.name);
        if r.outcome.ok() {
            writeln!(out, "{head}{}", label.green())?;
        } else if matches!(r.outcome, Outcome::Skipped(_)) {
            writeln!(out, "{head}{}", label.yellow())?;
        } else {
            writeln!(out, "{head}{}", label.red())?;
        }
    }
    Ok(())
}

fn confirm(count: usize, force: bool, out: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let sig = if force { "SIGKILL" } else { "SIGTERM -> SIGKILL" };
    write!(out, "\n对 {count} 个进程发送 {sig}? [y/N] ")?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// 交互式挑选:打印编号列表,读一行 `1,3-5` / `a` / `q`。
fn pick_interactive<'a>(
    entries: &'a [Entry],
    out: &mut impl Write,
) -> Result<Vec<&'a Entry>, Box<dyn Error>> {
    writeln!(out, "{}", "选择要清理的条目:".bold())?;
    for (i, e) in entries.iter().enumerate() {
        let mark = if e.protection.is_some() { " [受保护]" } else { "" };
        writeln!(
            out,
            "  {:>3}) :{:<6} {:<22} pid {:<7} {} {}{}",
            i + 1,
            e.port,
            e.proc.name,
            e.proc.pid,
            render::human_bytes(e.proc.rss_bytes),
            render::human_dur(e.proc.uptime_secs),
            mark
        )?;
    }
    write!(out, "\n编号(逗号/区间,a=全部,q=退出): ")?;
    out.flush()?;

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim();
    match line {
        "q" | "Q" | "" => Ok(Vec::new()),
        "a" | "A" => Ok(entries.iter().collect()),
        _ => {
            let idx = parse_index_spec(line, entries.len())?;
            Ok(idx.into_iter().map(|i| &entries[i]).collect())
        }
    }
}

/// 解析 `1,3-5` 形式的编号,返回 0-based 下标,已去重排序。
fn parse_index_spec(spec: &str, len: usize) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let lo: usize = lo.parse().map_err(|_| format!("非法编号: {lo}"))?;
        let hi: usize = hi.parse().map_err(|_| format!("非法编号: {hi}"))?;
        if lo == 0 || hi < lo || hi > len {
            return Err(format!("编号超出范围: {part}"));
        }
        out.extend(lo - 1..hi);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::parse_index_spec;

    #[test]
    fn index_spec() {
        assert_eq!(parse_index_spec("1,3-5", 6).unwrap(), vec![0, 2, 3, 4]);
        assert_eq!(parse_index_spec("2,2", 3).unwrap(), vec![1]);
        assert!(parse_index_spec("0", 3).is_err());
        assert!(parse_index_spec("4", 3).is_err());
        assert!(parse_index_spec("x", 3).is_err());
    }
}
