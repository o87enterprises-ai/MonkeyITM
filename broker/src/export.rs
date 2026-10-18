//! `broker export`: dump the event log to a file you can keep or share.

use eventlog::EventLog;
use serde_json::Value;
use std::io::Write;

pub const USAGE: &str = "\
usage: broker export [--format json|jsonl|text] [--out FILE] [--db FILE] [--since UNIX_SECS]

  --format   json (default): one document with a summary and every event
             jsonl: one event per line, for piping into other tools
             text: human-readable report
  --out      write to FILE instead of stdout
  --db       log to read (default: $BROKER_LOG, else broker.db)
  --since    only intents received at or after this unix timestamp

Safe to run while the broker is running. Capability tokens are never exported.";

pub fn run(args: &[String]) -> Result<(), String> {
    let mut format = "json".to_string();
    let mut out: Option<String> = None;
    let mut db =
        std::env::var("BROKER_LOG").unwrap_or_else(|_| crate::DEFAULT_LOG_PATH.to_string());
    let mut since: Option<i64> = None;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or(format!("{flag} needs a value\n\n{USAGE}"))
        };
        match flag.as_str() {
            "--format" => format = value()?,
            "--out" => out = Some(value()?),
            "--db" => db = value()?,
            "--since" => {
                since = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--since must be unix seconds".to_string())?,
                )
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }

    let log = EventLog::open_readonly(&db).map_err(|e| format!("can't open log {db}: {e}"))?;
    let doc = log
        .export(since)
        .map_err(|e| format!("export failed: {e}"))?;

    let body = match format.as_str() {
        "json" => serde_json::to_string_pretty(&doc).expect("json value serializes") + "\n",
        "jsonl" => doc["events"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| e.to_string() + "\n")
            .collect(),
        "text" => render_text(&doc),
        other => return Err(format!("unknown format: {other} (use json, jsonl or text)")),
    };

    match out {
        None => std::io::stdout()
            .write_all(body.as_bytes())
            .map_err(|e| e.to_string()),
        Some(path) => {
            if let Some(dir) = std::path::Path::new(&path)
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
            {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("can't create {}: {e}", dir.display()))?;
            }
            std::fs::write(&path, body).map_err(|e| format!("can't write {path}: {e}"))?;
            eprintln!(
                "broker: exported {} intent(s) to {path}",
                doc["summary"]["intents"]
            );
            Ok(())
        }
    }
}

fn render_text(doc: &Value) -> String {
    let s = &doc["summary"];
    let fv = &s["final_verdicts"];
    let he = &s["human_escalations"];
    let mut out = format!(
        "MonkeyITM-VM broker log\nexported {}\n\n\
         intents: {}   allow: {}   deny: {}   awaiting approval: {}\n\
         escalations: {} allowed by a human, {} denied by a human, {} pending, {} denied unattended\n\n",
        str_of(&doc["exported_at_utc"]),
        s["intents"],
        fv["allow"],
        fv["deny"],
        fv["approve_required"],
        he["allowed"],
        he["denied"],
        he["pending"],
        he["unattended_denied"],
    );
    for ev in doc["run_events"].as_array().into_iter().flatten() {
        out += &format!(
            "RUN {}  {}  {}\n\n",
            str_of(&ev["kind"]).to_uppercase(),
            str_of(&ev["at_utc"]),
            str_of(&ev["detail"])
        );
    }
    for ev in doc["job_events"].as_array().into_iter().flatten() {
        out += &format!(
            "JOB {}  {:<9}  {:<10}  {}  {}\n",
            str_of(&ev["job_id"]),
            str_of(&ev["source"]),
            str_of(&ev["kind"]).to_uppercase(),
            str_of(&ev["at_utc"]),
            str_of(&ev["detail"])
        );
    }
    if doc["job_events"].as_array().is_some_and(|a| !a.is_empty()) {
        out += "\n";
    }
    // Name the agent on each line only when the run had more than one.
    let group = doc["agents"].as_array().is_some_and(|a| !a.is_empty());
    for e in doc["events"].as_array().into_iter().flatten() {
        let verdict = str_of(&e["final_verdict"]).to_uppercase();
        let who = if group {
            format!("{:<4}", str_of(&e["agent"]))
        } else {
            String::new()
        };
        out += &format!(
            "{}  {who}{:<16}  {:<10}  {}\n",
            str_of(&e["received_at_utc"]),
            if verdict.is_empty() {
                "NO VERDICT"
            } else {
                &verdict
            },
            str_of(&e["action"]),
            e["params"],
        );
        if let Some(reason) = e["verdicts"]
            .as_array()
            .and_then(|v| v.last())
            .map(|v| str_of(&v["reason"]))
        {
            out += &format!("    reason: {reason}\n");
        }
        if let Some(j) = e["justification"].as_str() {
            out += &format!("    agent said: {j}\n");
        }
        for h in e["escalations"].as_array().into_iter().flatten() {
            out += &format!("    escalation: {}\n", str_of(&h["human_decision"]));
        }
        let r = &e["result"];
        if let Some(code) = r.get("exit_code") {
            out += &format!(
                "    exit code: {code}{}  ({} ms)\n",
                if r["timed_out"] == true {
                    ", timed out"
                } else {
                    ""
                },
                r["duration_ms"]
            );
            for (label, key) in [("stdout", "stdout"), ("stderr", "stderr")] {
                let text = str_of(&r[key]);
                if !text.trim().is_empty() {
                    out += &format!("    {label}: {}\n", indent(text.trim_end()));
                }
            }
        } else if let Some(n) = r.get("bytes_written") {
            out += &format!("    wrote {n} bytes (sha256 {})\n", str_of(&r["sha256"]));
        }
    }
    out
}

fn str_of(v: &Value) -> String {
    v.as_str().map(str::to_owned).unwrap_or_default()
}

fn indent(text: &str) -> String {
    text.lines().collect::<Vec<_>>().join("\n            ")
}
