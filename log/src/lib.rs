//! eventlog: append-only SQLite log for the broker.
//!
//! Three tables:
//!
//! - `intents`     — one row per intent that reached the broker, written
//!                   **before** the policy decision.
//! - `verdicts`    — one row per decision, written **after** the policy
//!                   decision and (on `allow`) after the capability is minted.
//! - `escalations` — one row per `approve_required` verdict, written when the
//!                   human is asked, then updated once with the human's answer.
//! - `job_events`  — web staging jobs (`broker stage`), one row per step, each
//!                   tagged with its source: broker, fetcher or sanitizer.
//!
//! Every write also appends an entry to `chain` (docs/LOG_CHAIN.md): a SHA-256 over the previous
//! entry's hash and the record's content, in the same transaction. `verify` rebuilds the chain and
//! checks every table row against it, so an edited, deleted, inserted or re-ordered row shows up.
//!
//! `intents` and `verdicts` are append-only. `escalations` has one narrow
//! mutation: `resolve_escalation` sets `resolved_at` + `decision` on the
//! pending row. That is the only UPDATE in this crate.

use intent::{Intent, Verdict};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub use rusqlite;

/// The agent a single-agent run, or a group's first agent, is recorded as.
pub const ROOT_AGENT: &str = "a1";

fn has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut q = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = q.query_map([], |r| r.get::<_, String>(1))?;
    for n in names {
        if n? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the first chain entry's `prev` is.
pub const CHAIN_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn chain_hash(prev: &str, kind: &str, payload: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(kind.as_bytes());
    h.update(b"\n");
    h.update(payload.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Append one entry to the chain. Call inside the transaction that wrote the row.
fn chain_append(conn: &Connection, kind: &str, ref_seq: i64, payload: &str) -> rusqlite::Result<()> {
    let prev: String = conn
        .query_row("SELECT hash FROM chain ORDER BY n DESC LIMIT 1", [], |r| r.get(0))
        .optional()?
        .unwrap_or_else(|| CHAIN_GENESIS.to_string());
    let hash = chain_hash(&prev, kind, payload);
    conn.execute(
        "INSERT INTO chain (kind, ref_seq, payload, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![kind, ref_seq, payload, prev, hash],
    )?;
    Ok(())
}

// The canonical content of each kind of record. Written once here and used both when a row is
// appended and when `verify` rebuilds it from the table, so the two cannot drift. Capability tokens
// are never part of a payload, only whether one was issued.
fn p_intent(id: &str, action: &str, params_json: &str, justification: Option<&str>, at: i64, agent: &str) -> String {
    serde_json::json!([id, action, params_json, justification, at, agent]).to_string()
}
fn p_verdict(intent_id: &str, verdict: &str, reason: &str, token_issued: bool, at: i64) -> String {
    serde_json::json!([intent_id, verdict, reason, token_issued, at]).to_string()
}
fn p_result(intent_id: &str, result_json: &str, at: i64) -> String {
    serde_json::json!([intent_id, result_json, at]).to_string()
}
fn p_run(kind: &str, detail: &str, at: i64) -> String {
    serde_json::json!([kind, detail, at]).to_string()
}
fn p_job(job_id: &str, source: &str, kind: &str, detail: &str, at: i64) -> String {
    serde_json::json!([job_id, source, kind, detail, at]).to_string()
}
fn p_esc_requested(intent_id: &str, at: i64) -> String {
    serde_json::json!([intent_id, at]).to_string()
}
fn p_esc_resolved(intent_id: &str, decision: &str, at: i64) -> String {
    serde_json::json!([intent_id, decision, at]).to_string()
}

/// The outcome of `EventLog::verify`.
#[derive(Debug, Clone)]
pub struct ChainReport {
    pub ok: bool,
    /// Entries in the chain.
    pub rows: i64,
    /// The hash of the last entry: record it somewhere the log's keeper cannot change.
    pub head: String,
    pub problems: Vec<String>,
}

pub struct EventLog {
    conn: Connection,
}

impl EventLog {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    /// Open an existing log for export without writing to it, so it is safe to
    /// run while the broker still has the file open.
    pub fn open_readonly(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    pub fn in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    fn init(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS intents (
                seq             INTEGER PRIMARY KEY AUTOINCREMENT,
                id              TEXT NOT NULL,
                action          TEXT NOT NULL,
                params_json     TEXT NOT NULL,
                justification   TEXT,
                received_at     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verdicts (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_id   TEXT NOT NULL,
                verdict     TEXT NOT NULL,
                reason      TEXT NOT NULL,
                token       TEXT,
                decided_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS escalations (
                seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_id    TEXT NOT NULL,
                requested_at INTEGER NOT NULL,
                resolved_at  INTEGER,
                decision     TEXT
            );

            CREATE TABLE IF NOT EXISTS results (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_id   TEXT NOT NULL,
                result_json TEXT NOT NULL,
                recorded_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS run_events (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                kind        TEXT NOT NULL,
                detail      TEXT NOT NULL,
                at          INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS job_events (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id      TEXT NOT NULL,
                source      TEXT NOT NULL,
                kind        TEXT NOT NULL,
                detail      TEXT NOT NULL,
                at          INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chain (
                n        INTEGER PRIMARY KEY AUTOINCREMENT,
                kind     TEXT NOT NULL,
                ref_seq  INTEGER NOT NULL,
                payload  TEXT NOT NULL,
                prev     TEXT NOT NULL,
                hash     TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_intents_id ON intents(id);
            CREATE INDEX IF NOT EXISTS idx_results_intent_id ON results(intent_id);
            CREATE INDEX IF NOT EXISTS idx_verdicts_intent_id ON verdicts(intent_id);
            CREATE INDEX IF NOT EXISTS idx_escalations_intent_id ON escalations(intent_id);
            "#,
        )?;
        // Logs written before agents had ids: add the column; old rows are the root.
        if !has_column(conn, "intents", "agent")? {
            conn.execute_batch(&format!(
                "ALTER TABLE intents ADD COLUMN agent TEXT NOT NULL DEFAULT '{ROOT_AGENT}'"
            ))?;
        }
        Ok(())
    }

    pub fn record_intent(&self, intent: &Intent) -> rusqlite::Result<i64> {
        self.record_intent_as(ROOT_AGENT, intent)
    }

    /// `agent` is who the broker knows sent the intent (from the socket it
    /// arrived on), never anything the intent says about itself.
    pub fn record_intent_as(&self, agent: &str, intent: &Intent) -> rusqlite::Result<i64> {
        let params_json = serde_json::to_string(&intent.params)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let (action, at) = (enum_str(&intent.action), now_secs());
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO intents (id, action, params_json, justification, received_at, agent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![intent.id, action, params_json, &intent.justification, at, agent],
        )?;
        let seq = tx.last_insert_rowid();
        chain_append(&tx, "intent", seq, &p_intent(&intent.id, &action, &params_json, Some(intent.justification.as_str()), at, agent))?;
        tx.commit()?;
        Ok(seq)
    }

    pub fn record_verdict(&self, verdict: &Verdict) -> rusqlite::Result<i64> {
        let (kind, at) = (enum_str(&verdict.verdict), now_secs());
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO verdicts (intent_id, verdict, reason, token, decided_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![verdict.id, kind, verdict.reason, &verdict.token, at],
        )?;
        let seq = tx.last_insert_rowid();
        chain_append(&tx, "verdict", seq, &p_verdict(&verdict.id, &kind, &verdict.reason, verdict.token.is_some(), at))?;
        tx.commit()?;
        Ok(seq)
    }

    /// What an allowed action returned (or a summary of it), written after
    /// execution and before the verdict row.
    pub fn record_result(
        &self,
        intent_id: &str,
        result: &serde_json::Value,
    ) -> rusqlite::Result<i64> {
        let (text, at) = (result.to_string(), now_secs());
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO results (intent_id, result_json, recorded_at) VALUES (?1, ?2, ?3)",
            params![intent_id, text, at],
        )?;
        let seq = tx.last_insert_rowid();
        chain_append(&tx, "result", seq, &p_result(intent_id, &text, at))?;
        tx.commit()?;
        Ok(seq)
    }

    /// A run-level event, such as the tripwire halting the run.
    pub fn record_run_event(&self, kind: &str, detail: &str) -> rusqlite::Result<i64> {
        let at = now_secs();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO run_events (kind, detail, at) VALUES (?1, ?2, ?3)",
            params![kind, detail, at],
        )?;
        let seq = tx.last_insert_rowid();
        chain_append(&tx, "run_event", seq, &p_run(kind, detail, at))?;
        tx.commit()?;
        Ok(seq)
    }

    /// One step of a web staging job, tagged with who did it: `broker`,
    /// `fetcher` or `sanitizer`. The agent's own requests stay in `intents`.
    pub fn record_job_event(
        &self,
        job_id: &str,
        source: &str,
        kind: &str,
        detail: &str,
    ) -> rusqlite::Result<i64> {
        let at = now_secs();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO job_events (job_id, source, kind, detail, at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![job_id, source, kind, detail, at],
        )?;
        let seq = tx.last_insert_rowid();
        chain_append(&tx, "job_event", seq, &p_job(job_id, source, kind, detail, at))?;
        tx.commit()?;
        Ok(seq)
    }

    /// Record that a human was asked. `resolved_at` and `decision` stay NULL.
    pub fn record_escalation_requested(&self, intent_id: &str) -> rusqlite::Result<i64> {
        let at = now_secs();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO escalations (intent_id, requested_at) VALUES (?1, ?2)",
            params![intent_id, at],
        )?;
        let seq = tx.last_insert_rowid();
        chain_append(&tx, "escalation_requested", seq, &p_esc_requested(intent_id, at))?;
        tx.commit()?;
        Ok(seq)
    }

    /// Set the human's answer on the most recent pending escalation for this
    /// intent. `decision` is "allow" or "deny".
    pub fn resolve_escalation(&self, intent_id: &str, decision: &str) -> rusqlite::Result<usize> {
        let at = now_secs();
        let tx = self.conn.unchecked_transaction()?;
        let seq: Option<i64> = tx
            .query_row(
                "SELECT MAX(seq) FROM escalations WHERE intent_id = ?1 AND resolved_at IS NULL",
                [intent_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(seq) = seq else { return Ok(0) };
        let n = tx.execute(
            "UPDATE escalations SET resolved_at = ?1, decision = ?2 WHERE seq = ?3",
            params![at, decision, seq],
        )?;
        chain_append(&tx, "escalation_resolved", seq, &p_esc_resolved(intent_id, decision, at))?;
        tx.commit()?;
        Ok(n)
    }

    pub fn count_intents(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM intents", [], |r| r.get(0))
    }

    pub fn count_verdicts(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM verdicts", [], |r| r.get(0))
    }

    pub fn count_escalations(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM escalations", [], |r| r.get(0))
    }

    pub fn pending_escalation_count(&self) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM escalations WHERE resolved_at IS NULL",
            [],
            |r| r.get(0),
        )
    }

    pub fn latest_verdict_for(&self, intent_id: &str) -> rusqlite::Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT verdict FROM verdicts WHERE intent_id = ?1 ORDER BY seq DESC LIMIT 1",
        )?;
        let mut rows = stmt.query([intent_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn latest_escalation_decision(&self, intent_id: &str) -> rusqlite::Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT decision FROM escalations WHERE intent_id = ?1 ORDER BY seq DESC LIMIT 1",
        )?;
        let mut rows = stmt.query([intent_id])?;
        if let Some(row) = rows.next()? {
            Ok(row.get(0)?)
        } else {
            Ok(None)
        }
    }
}

impl EventLog {
    /// Every intent at or after `since` (unix seconds), oldest first, each with
    /// its verdicts and human escalations attached, plus a summary.
    ///
    /// Capability tokens are never exported, only whether one was issued: the
    /// file is meant to be shared.
    pub fn export(&self, since: Option<i64>) -> rusqlite::Result<serde_json::Value> {
        use serde_json::{Value, json};
        let since = since.unwrap_or(i64::MIN);

        let mut verdicts_q = self.conn.prepare(
            "SELECT verdict, reason, token IS NOT NULL, decided_at
             FROM verdicts WHERE intent_id = ?1 ORDER BY seq",
        )?;
        let mut escalations_q = self.conn.prepare(
            "SELECT requested_at, resolved_at, decision
             FROM escalations WHERE intent_id = ?1 ORDER BY seq",
        )?;
        let has_results: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'results'",
            [],
            |r| r.get(0),
        )?;
        let mut results_q = has_results
            .then(|| {
                self.conn.prepare(
                    "SELECT result_json FROM results WHERE intent_id = ?1 ORDER BY seq DESC LIMIT 1",
                )
            })
            .transpose()?;
        // A read-only open of an old log has no agent column; its rows are the root's.
        let agent_col = if has_column(&self.conn, "intents", "agent")? {
            "agent".to_string()
        } else {
            format!("'{ROOT_AGENT}'")
        };
        let mut intents_q = self.conn.prepare(&format!(
            "SELECT seq, id, action, params_json, justification, received_at, {agent_col}
             FROM intents WHERE received_at >= ?1 ORDER BY seq"
        ))?;

        type Row = (i64, String, String, String, Option<String>, i64, String);
        let rows: Vec<Row> = intents_q
            .query_map([since], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;

        let (mut allow, mut deny, mut approve_required) = (0, 0, 0);
        let (mut human_allowed, mut human_denied, mut pending, mut unattended) = (0, 0, 0, 0);
        let mut events = Vec::with_capacity(rows.len());

        for (seq, id, action, params_json, justification, received_at, agent) in rows {
            let verdicts: Vec<Value> = verdicts_q
                .query_map([&id], |r| {
                    let (v, reason, token, at): (String, String, bool, i64) =
                        (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
                    Ok(json!({
                        "verdict": v, "reason": reason, "capability_issued": token,
                        "decided_at": at, "decided_at_utc": iso8601(at),
                    }))
                })?
                .collect::<rusqlite::Result<_>>()?;
            let escalations: Vec<Value> = escalations_q
                .query_map([&id], |r| {
                    let (req, res, dec): (i64, Option<i64>, Option<String>) =
                        (r.get(0)?, r.get(1)?, r.get(2)?);
                    Ok(json!({
                        "requested_at": req, "resolved_at": res,
                        "human_decision": dec.unwrap_or_else(|| "pending".into()),
                    }))
                })?
                .collect::<rusqlite::Result<_>>()?;

            match verdicts.last().and_then(|v| v["verdict"].as_str()) {
                Some("allow") => allow += 1,
                Some("approve_required") => approve_required += 1,
                _ => deny += 1,
            }
            for e in &escalations {
                match e["human_decision"].as_str() {
                    Some("allow") => human_allowed += 1,
                    Some("deny") => human_denied += 1,
                    Some("unattended") => unattended += 1,
                    _ => pending += 1,
                }
            }

            let result: Value = match results_q.as_mut() {
                Some(q) => q
                    .query_row([&id], |r| r.get::<_, String>(0))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Null),
                None => Value::Null,
            };
            let params: Value =
                serde_json::from_str(&params_json).unwrap_or(Value::String(params_json));
            events.push(json!({
                "seq": seq, "intent_id": id, "agent": agent, "action": action, "params": params,
                "justification": justification,
                "received_at": received_at, "received_at_utc": iso8601(received_at),
                "final_verdict": verdicts.last().map(|v| v["verdict"].clone()).unwrap_or(Value::Null),
                "verdicts": verdicts, "escalations": escalations, "result": result,
            }));
        }

        let has_run_events: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'run_events'",
            [],
            |r| r.get(0),
        )?;
        let run_events: Vec<Value> = if has_run_events {
            let mut q = self
                .conn
                .prepare("SELECT kind, detail, at FROM run_events WHERE at >= ?1 ORDER BY seq")?;
            q.query_map([since], |r| {
                let (kind, detail, at): (String, String, i64) = (r.get(0)?, r.get(1)?, r.get(2)?);
                Ok(json!({ "kind": kind, "detail": detail, "at": at, "at_utc": iso8601(at) }))
            })?
            .collect::<rusqlite::Result<_>>()?
        } else {
            Vec::new()
        };
        let halted = run_events.iter().any(|e| e["kind"] == "tripwire");
        let killed_by_owner = run_events.iter().any(|e| e["kind"] == "kill_switch");

        // Who started whom and how each child ended, from the run events.
        let mut agents: Vec<Value> = Vec::new();
        for e in &run_events {
            let detail: Value = e["detail"]
                .as_str()
                .and_then(|d| serde_json::from_str(d).ok())
                .unwrap_or(Value::Null);
            match e["kind"].as_str() {
                Some("agent_spawned") => agents.push(json!({
                    "agent": detail["agent"], "parent": detail["parent"],
                    "task": detail["task"], "started_at_utc": e["at_utc"],
                    "ended_at_utc": Value::Null, "end": Value::Null,
                })),
                Some("agent_exited") => {
                    if let Some(a) = agents.iter_mut().find(|a| a["agent"] == detail["agent"]) {
                        a["ended_at_utc"] = e["at_utc"].clone();
                        a["end"] = detail["reason"].clone();
                    }
                }
                _ => {}
            }
        }

        let has_job_events: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'job_events'",
            [],
            |r| r.get(0),
        )?;
        let job_events: Vec<Value> = if has_job_events {
            let mut q = self.conn.prepare(
                "SELECT job_id, source, kind, detail, at FROM job_events WHERE at >= ?1 ORDER BY seq",
            )?;
            q.query_map([since], |r| {
                let (job, source, kind, detail, at): (String, String, String, String, i64) =
                    (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
                Ok(json!({
                    "job_id": job, "source": source, "kind": kind, "detail": detail,
                    "at": at, "at_utc": iso8601(at),
                }))
            })?
            .collect::<rusqlite::Result<_>>()?
        } else {
            Vec::new()
        };
        let count_source = |s: &str| job_events.iter().filter(|e| e["source"] == s).count();
        let alarms = job_events.iter().filter(|e| e["kind"] == "alarm").count();

        let chain = self.chain_summary()?;
        Ok(json!({
            "format": "monkeyitm-log/v1",
            "exported_at": now_secs(), "exported_at_utc": iso8601(now_secs()),
            "summary": {
                "intents": events.len(),
                "halted_by_tripwire": halted,
                "killed_by_owner": killed_by_owner,
                "chain": chain,
                "final_verdicts": { "allow": allow, "deny": deny, "approve_required": approve_required },
                "human_escalations": { "allowed": human_allowed, "denied": human_denied, "pending": pending, "unattended_denied": unattended },
                "job_events": {
                    "broker": count_source("broker"), "fetcher": count_source("fetcher"),
                    "sanitizer": count_source("sanitizer"), "alarms": alarms,
                },
            },
            "events": events,
            "agents": agents,
            "run_events": run_events,
            "job_events": job_events,
        }))
    }
}

impl EventLog {
    fn has_table(&self, name: &str) -> rusqlite::Result<bool> {
        self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |r| r.get(0),
        )
    }

    /// `{algorithm, rows, head}` for the export summary, or null for a log written before chaining.
    pub fn chain_summary(&self) -> rusqlite::Result<serde_json::Value> {
        if !self.has_table("chain")? {
            return Ok(serde_json::Value::Null);
        }
        let rows: i64 = self.conn.query_row("SELECT COUNT(*) FROM chain", [], |r| r.get(0))?;
        let head: String = self
            .conn
            .query_row("SELECT hash FROM chain ORDER BY n DESC LIMIT 1", [], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| CHAIN_GENESIS.to_string());
        Ok(serde_json::json!({ "algorithm": "sha256", "rows": rows, "head": head }))
    }

    /// Rebuild the chain and check every row against it. Finds an edited, deleted, inserted or
    /// re-ordered row, and a chain entry that was altered or removed. It cannot tell that the *end*
    /// of the log was cut off, or that the whole log was rewritten from the start, unless you also
    /// compare `head` and `rows` with a copy kept somewhere else (`verify_against`).
    pub fn verify(&self) -> rusqlite::Result<ChainReport> {
        let mut problems: Vec<String> = Vec::new();
        let mut note = |p: String| problems.push(p);
        if !self.has_table("chain")? {
            return Ok(ChainReport {
                ok: false,
                rows: 0,
                head: CHAIN_GENESIS.to_string(),
                problems: vec!["this log has no hash chain (it was written before chaining)".into()],
            });
        }
        let agent_col = if has_column(&self.conn, "intents", "agent")? {
            "agent".to_string()
        } else {
            format!("'{ROOT_AGENT}'")
        };

        // 1. The chain itself: contiguous, linked, and each hash right for its content.
        let mut q = self.conn.prepare("SELECT n, kind, ref_seq, payload, prev, hash FROM chain ORDER BY n")?;
        let entries: Vec<(i64, String, i64, String, String, String)> = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut running = CHAIN_GENESIS.to_string();
        let mut expect_n = 1;
        let mut referenced: HashMap<&str, HashSet<i64>> = HashMap::new();
        for (n, kind, ref_seq, payload, prev, hash) in &entries {
            if *n != expect_n {
                note(format!("chain entry {expect_n} is missing (found {n})"));
                expect_n = *n;
            }
            expect_n += 1;
            if *prev != running {
                note(format!("chain entry {n} does not follow the one before it (an entry was removed, inserted or altered)"));
            }
            if chain_hash(prev, kind, payload) != *hash {
                note(format!("chain entry {n} ({kind}) does not match its own hash (its content was altered)"));
            }
            running = hash.clone();

            // 2. The row the entry stands for must still say the same thing.
            let (table, key): (&str, &str) = match kind.as_str() {
                "intent" => ("intents", "intent"),
                "verdict" => ("verdicts", "verdict"),
                "result" => ("results", "result"),
                "run_event" => ("run_events", "run_event"),
                "job_event" => ("job_events", "job_event"),
                "escalation_requested" | "escalation_resolved" => ("escalations", "escalation"),
                other => {
                    note(format!("chain entry {n} has an unknown kind: {other}"));
                    continue;
                }
            };
            if kind != "escalation_resolved" {
                referenced.entry(key).or_default().insert(*ref_seq);
            }
            let rebuilt: Option<String> = match kind.as_str() {
                "intent" => self
                    .conn
                    .query_row(
                        &format!("SELECT id, action, params_json, justification, received_at, {agent_col} FROM intents WHERE seq = ?1"),
                        [ref_seq],
                        |r| Ok(p_intent(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?, &r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?.as_deref(), r.get(4)?, &r.get::<_, String>(5)?)),
                    )
                    .optional()?,
                "verdict" => self
                    .conn
                    .query_row("SELECT intent_id, verdict, reason, token IS NOT NULL, decided_at FROM verdicts WHERE seq = ?1", [ref_seq],
                        |r| Ok(p_verdict(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?, &r.get::<_, String>(2)?, r.get(3)?, r.get(4)?)))
                    .optional()?,
                "result" => self
                    .conn
                    .query_row("SELECT intent_id, result_json, recorded_at FROM results WHERE seq = ?1", [ref_seq],
                        |r| Ok(p_result(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?, r.get(2)?)))
                    .optional()?,
                "run_event" => self
                    .conn
                    .query_row("SELECT kind, detail, at FROM run_events WHERE seq = ?1", [ref_seq],
                        |r| Ok(p_run(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?, r.get(2)?)))
                    .optional()?,
                "job_event" => self
                    .conn
                    .query_row("SELECT job_id, source, kind, detail, at FROM job_events WHERE seq = ?1", [ref_seq],
                        |r| Ok(p_job(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?, &r.get::<_, String>(2)?, &r.get::<_, String>(3)?, r.get(4)?)))
                    .optional()?,
                "escalation_requested" => self
                    .conn
                    .query_row("SELECT intent_id, requested_at FROM escalations WHERE seq = ?1", [ref_seq],
                        |r| Ok(p_esc_requested(&r.get::<_, String>(0)?, r.get(1)?)))
                    .optional()?,
                _ => self // escalation_resolved
                    .conn
                    .query_row("SELECT intent_id, decision, resolved_at FROM escalations WHERE seq = ?1 AND resolved_at IS NOT NULL", [ref_seq],
                        |r| Ok(p_esc_resolved(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?, r.get(2)?)))
                    .optional()?,
            };
            match rebuilt {
                None => note(format!("chain entry {n} ({kind}) refers to a {table} row that is gone or no longer resolved")),
                Some(p) if p != *payload => note(format!("the {table} row #{ref_seq} was changed after chain entry {n} recorded it")),
                Some(_) => {}
            }
        }

        // 3. Every row in the tables must be in the chain: nothing slipped in beside it.
        for (table, key) in [("intents", "intent"), ("verdicts", "verdict"), ("results", "result"), ("run_events", "run_event"),
                             ("job_events", "job_event"), ("escalations", "escalation")] {
            if !self.has_table(table)? {
                continue;
            }
            let mut q = self.conn.prepare(&format!("SELECT seq FROM {table}"))?;
            let seqs: Vec<i64> = q.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            let have = referenced.get(key);
            let loose = seqs.iter().filter(|s| !have.is_some_and(|h| h.contains(s))).count();
            if loose > 0 {
                note(format!("{loose} {table} row(s) are not in the chain (inserted without it, or written before chaining)"));
            }
        }

        let rows = entries.len() as i64;
        drop(note);
        let total = problems.len();
        if total > 20 {
            problems.truncate(20);
            problems.push(format!("... and {} more", total - 20));
        }
        Ok(ChainReport { ok: total == 0, rows, head: running, problems })
    }

    /// `verify`, plus a comparison with a head and a row count kept elsewhere: this is what catches
    /// a log cut short, or rewritten from the start.
    pub fn verify_against(&self, head: Option<&str>, rows: Option<i64>) -> rusqlite::Result<ChainReport> {
        let mut r = self.verify()?;
        if let Some(head) = head {
            if r.head != head {
                r.ok = false;
                r.problems.push(format!("the head of the chain is {} but {} was expected (the log was cut short, extended or rewritten)", r.head, head));
            }
        }
        if let Some(n) = rows {
            if r.rows != n {
                r.ok = false;
                r.problems.push(format!("the chain has {} entries but {n} were expected", r.rows));
            }
        }
        Ok(r)
    }
}

/// Unix seconds to `YYYY-MM-DDTHH:MM:SSZ` (UTC), without a date-time dependency.
pub fn iso8601(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<non-string-enum>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent::{Action, VerdictKind};
    use serde_json::json;

    fn sample_intent() -> Intent {
        Intent::new(Action::ReadFile, json!({"path": "/tmp/safe/x.txt"}))
    }

    fn verdict_for(id: &str, kind: VerdictKind) -> Verdict {
        Verdict {
            id: id.to_string(),
            verdict: kind,
            result: serde_json::Value::Null,
            reason: "test".into(),
            token: None,
        }
    }

    // NOTE: `intents.seq` and `verdicts.seq` are independent AUTOINCREMENT
    // counters, so we cannot compare them across tables. Ordering of writes
    // (intent first, verdict second) is the broker's responsibility.
    #[test]
    fn record_intent_and_verdict_each_produce_one_row() {
        let log = EventLog::in_memory().unwrap();
        let intent = sample_intent();
        log.record_intent(&intent).unwrap();
        log.record_verdict(&verdict_for(&intent.id, VerdictKind::Allow))
            .unwrap();
        assert_eq!(log.count_intents().unwrap(), 1);
        assert_eq!(log.count_verdicts().unwrap(), 1);
    }

    #[test]
    fn orphan_intent_row_survives_without_verdict() {
        let log = EventLog::in_memory().unwrap();
        let intent = sample_intent();
        log.record_intent(&intent).unwrap();
        assert_eq!(log.count_intents().unwrap(), 1);
        assert_eq!(log.count_verdicts().unwrap(), 0);
        assert!(log.latest_verdict_for(&intent.id).unwrap().is_none());
    }

    #[test]
    fn latest_verdict_for_returns_most_recent() {
        let log = EventLog::in_memory().unwrap();
        let intent = sample_intent();
        log.record_intent(&intent).unwrap();
        for v in [VerdictKind::ApproveRequired, VerdictKind::Allow] {
            log.record_verdict(&verdict_for(&intent.id, v)).unwrap();
        }
        assert_eq!(
            log.latest_verdict_for(&intent.id).unwrap().as_deref(),
            Some("allow"),
        );
    }

    #[test]
    fn escalation_lifecycle_request_then_resolve() {
        let log = EventLog::in_memory().unwrap();
        log.record_escalation_requested("i1").unwrap();
        assert_eq!(log.count_escalations().unwrap(), 1);
        assert_eq!(log.pending_escalation_count().unwrap(), 1);
        assert!(log.latest_escalation_decision("i1").unwrap().is_none());

        log.resolve_escalation("i1", "allow").unwrap();
        assert_eq!(log.pending_escalation_count().unwrap(), 0);
        assert_eq!(
            log.latest_escalation_decision("i1").unwrap().as_deref(),
            Some("allow"),
        );
    }

    #[test]
    fn export_attaches_result_and_counts_unattended() {
        let log = EventLog::in_memory().unwrap();
        let intent = sample_intent();
        log.record_intent(&intent).unwrap();
        log.record_result(&intent.id, &json!({"exit_code": 0}))
            .unwrap();
        log.record_verdict(&verdict_for(&intent.id, VerdictKind::Allow))
            .unwrap();
        let other = sample_intent();
        log.record_intent(&other).unwrap();
        log.record_escalation_requested(&other.id).unwrap();
        log.resolve_escalation(&other.id, "unattended").unwrap();
        log.record_verdict(&verdict_for(&other.id, VerdictKind::Deny))
            .unwrap();

        let out = log.export(None).unwrap();
        assert_eq!(out["events"][0]["result"]["exit_code"], 0);
        assert!(out["events"][1]["result"].is_null());
        assert_eq!(out["summary"]["human_escalations"]["unattended_denied"], 1);
        assert_eq!(out["summary"]["human_escalations"]["pending"], 0);
    }

    #[test]
    fn iso8601_known_values() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_790_000_000), "2026-09-21T14:13:20Z");
    }

    #[test]
    fn export_attaches_verdicts_and_escalations_and_hides_tokens() {
        let log = EventLog::in_memory().unwrap();
        let intent = sample_intent();
        log.record_intent(&intent).unwrap();
        log.record_escalation_requested(&intent.id).unwrap();
        log.resolve_escalation(&intent.id, "allow").unwrap();
        let mut v = verdict_for(&intent.id, VerdictKind::Allow);
        v.token = Some("secret-capability-token".into());
        log.record_verdict(&v).unwrap();

        let out = log.export(None).unwrap();
        assert_eq!(out["summary"]["intents"], 1);
        assert_eq!(out["summary"]["final_verdicts"]["allow"], 1);
        assert_eq!(out["summary"]["human_escalations"]["allowed"], 1);
        let e = &out["events"][0];
        assert_eq!(e["action"], "read_file");
        assert_eq!(e["params"]["path"], "/tmp/safe/x.txt");
        assert_eq!(e["final_verdict"], "allow");
        assert_eq!(e["verdicts"][0]["capability_issued"], true);
        assert!(!out.to_string().contains("secret-capability-token"));

        assert_eq!(log.export(Some(i64::MAX)).unwrap()["summary"]["intents"], 0);
    }

    #[test]
    fn resolve_escalation_is_noop_when_nothing_pending() {
        let log = EventLog::in_memory().unwrap();
        let n = log.resolve_escalation("i-nope", "deny").unwrap();
        assert_eq!(n, 0, "no rows should be updated");
        assert_eq!(log.pending_escalation_count().unwrap(), 0);
    }

    #[test]
    fn resolve_only_touches_the_most_recent_pending_row() {
        let log = EventLog::in_memory().unwrap();
        log.record_escalation_requested("i1").unwrap();
        log.resolve_escalation("i1", "deny").unwrap();
        log.record_escalation_requested("i1").unwrap();

        assert_eq!(log.pending_escalation_count().unwrap(), 1);
        log.resolve_escalation("i1", "allow").unwrap();
        assert_eq!(log.pending_escalation_count().unwrap(), 0);
        assert_eq!(log.count_escalations().unwrap(), 2);
        assert_eq!(
            log.latest_escalation_decision("i1").unwrap().as_deref(),
            Some("allow"),
        );
    }

    #[test]
    fn records_which_agent_sent_the_intent_and_exports_it() {
        let log = EventLog::in_memory().unwrap();
        let a = sample_intent();
        let b = sample_intent();
        log.record_intent(&a).unwrap();
        log.record_intent_as("a2", &b).unwrap();

        let out = log.export(None).unwrap();
        assert_eq!(out["events"][0]["agent"], ROOT_AGENT);
        assert_eq!(out["events"][1]["agent"], "a2");
    }

    #[test]
    fn a_log_from_before_agent_ids_gains_the_column_and_keeps_its_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE intents (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL,
                action TEXT NOT NULL, params_json TEXT NOT NULL,
                justification TEXT, received_at INTEGER NOT NULL);
             INSERT INTO intents (id, action, params_json, justification, received_at)
             VALUES ('old', 'read_file', '{}', '', 1);",
        )
        .unwrap();
        EventLog::init(&conn).unwrap();
        let log = EventLog { conn };
        log.record_intent_as("a3", &sample_intent()).unwrap();

        let out = log.export(None).unwrap();
        assert_eq!(out["events"][0]["intent_id"], "old");
        assert_eq!(out["events"][0]["agent"], ROOT_AGENT);
        assert_eq!(out["events"][1]["agent"], "a3");
    }

    #[test]
    fn export_lists_child_agents_from_run_events() {
        let log = EventLog::in_memory().unwrap();
        log.record_run_event(
            "agent_spawned",
            r#"{"agent":"a2","parent":"a1","task":"t","max_steps":8}"#,
        )
        .unwrap();
        log.record_run_event(
            "agent_exited",
            r#"{"agent":"a2","reason":"killed by the broker"}"#,
        )
        .unwrap();
        let out = log.export(None).unwrap();
        assert_eq!(out["agents"][0]["agent"], "a2");
        assert_eq!(out["agents"][0]["parent"], "a1");
        assert_eq!(out["agents"][0]["end"], "killed by the broker");
    }
}
