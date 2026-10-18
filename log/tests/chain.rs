//! The log's hash chain: every write is chained, and `verify` finds any change made outside the
//! broker. Tampering here uses a second connection to the same file, as an attacker with the
//! database file would.

use eventlog::{CHAIN_GENESIS, EventLog, rusqlite::Connection};
use intent::{Action, Intent, Verdict, VerdictKind};
use serde_json::json;
use std::path::PathBuf;

fn temp_db(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("chain-test-{tag}-{}-{}.db", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let _ = std::fs::remove_file(&p);
    p
}

fn verdict(id: &str, kind: VerdictKind, token: Option<&str>) -> Verdict {
    Verdict { id: id.to_string(), verdict: kind, result: serde_json::Value::Null, reason: "because".into(), token: token.map(str::to_string) }
}

/// A small honest log: three intents with verdicts, a result, a run event, an escalation.
fn honest(path: &PathBuf) -> EventLog {
    let log = EventLog::open(path).unwrap();
    for (i, p) in ["/tmp/safe/a", "/tmp/safe/b", "/etc/passwd"].iter().enumerate() {
        let it = Intent::new(Action::ReadFile, json!({ "path": p }));
        log.record_intent(&it).unwrap();
        if i < 2 {
            log.record_result(&it.id, &json!({ "content": "x" })).unwrap();
            log.record_verdict(&verdict(&it.id, VerdictKind::Allow, Some("secret-token"))).unwrap();
        } else {
            log.record_escalation_requested(&it.id).unwrap();
            log.resolve_escalation(&it.id, "deny").unwrap();
            log.record_verdict(&verdict(&it.id, VerdictKind::Deny, None)).unwrap();
        }
    }
    log.record_run_event("tripwire", "3 denied").unwrap();
    log.record_job_event("job-1", "broker", "step", "ok").unwrap();
    log
}

fn tamper(path: &PathBuf, sql: &str) {
    Connection::open(path).unwrap().execute_batch(sql).unwrap();
}

fn problems(path: &PathBuf) -> Vec<String> {
    EventLog::open_readonly(path).unwrap().verify().unwrap().problems
}

#[test]
fn an_honest_log_verifies_and_the_head_moves_with_every_write() {
    let path = temp_db("honest");
    let log = EventLog::open(&path).unwrap();
    let empty = log.verify().unwrap();
    assert!(empty.ok && empty.rows == 0 && empty.head == CHAIN_GENESIS, "{empty:?}");
    let it = Intent::new(Action::ReadFile, json!({ "path": "/tmp/safe/a" }));
    log.record_intent(&it).unwrap();
    let one = log.verify().unwrap();
    log.record_verdict(&verdict(&it.id, VerdictKind::Deny, None)).unwrap();
    let two = log.verify().unwrap();
    assert!(one.ok && two.ok && one.rows == 1 && two.rows == 2 && one.head != two.head && two.head != CHAIN_GENESIS);
    drop(log);
    let log = honest(&temp_db("honest2"));
    let r = log.verify().unwrap();
    assert!(r.ok, "{:?}", r.problems);
    assert!(r.rows >= 12, "every kind of record is chained: {}", r.rows);
}

#[test]
fn the_export_carries_the_head_and_the_count() {
    let log = honest(&temp_db("export"));
    let doc = log.export(None).unwrap();
    let r = log.verify().unwrap();
    assert_eq!(doc["summary"]["chain"]["head"], r.head);
    assert_eq!(doc["summary"]["chain"]["rows"], r.rows);
    assert_eq!(doc["summary"]["chain"]["algorithm"], "sha256");
    let text = doc.to_string();
    assert!(!text.contains("secret-token"), "tokens never leave the log");
}

#[test]
fn capability_tokens_are_not_in_the_chain() {
    let path = temp_db("tokens");
    honest(&path);
    let c = Connection::open(&path).unwrap();
    let payloads: Vec<String> = c.prepare("SELECT payload FROM chain").unwrap().query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
    assert!(payloads.iter().all(|p| !p.contains("secret-token")));
}

#[test]
fn an_edited_verdict_is_found() {
    let path = temp_db("edit");
    honest(&path);
    tamper(&path, "UPDATE verdicts SET verdict = 'allow' WHERE seq = 3");
    let p = problems(&path);
    assert!(p.iter().any(|m| m.contains("verdicts row #3 was changed")), "{p:?}");
}

#[test]
fn an_edited_result_and_an_edited_request_are_found() {
    let path = temp_db("edit2");
    honest(&path);
    tamper(&path, "UPDATE results SET result_json = '{}' WHERE seq = 1; UPDATE intents SET params_json = '{\"path\":\"/tmp/safe/z\"}' WHERE seq = 3");
    let p = problems(&path);
    assert!(p.iter().any(|m| m.contains("results row #1")) && p.iter().any(|m| m.contains("intents row #3")), "{p:?}");
}

#[test]
fn a_deleted_record_is_found() {
    let path = temp_db("delete");
    honest(&path);
    tamper(&path, "DELETE FROM intents WHERE seq = 2");
    let p = problems(&path);
    assert!(p.iter().any(|m| m.contains("gone")), "{p:?}");
}

#[test]
fn a_record_inserted_without_the_chain_is_found() {
    let path = temp_db("insert");
    honest(&path);
    tamper(&path, "INSERT INTO verdicts (intent_id, verdict, reason, token, decided_at) VALUES ('x', 'allow', 'forged', NULL, 1)");
    let p = problems(&path);
    assert!(p.iter().any(|m| m.contains("1 verdicts row(s) are not in the chain")), "{p:?}");
}

#[test]
fn an_altered_chain_entry_is_found() {
    let path = temp_db("chainedit");
    honest(&path);
    tamper(&path, "UPDATE chain SET payload = '[\"x\"]' WHERE n = 4");
    let p = problems(&path);
    assert!(p.iter().any(|m| m.contains("chain entry 4") && m.contains("own hash")), "{p:?}");
}

#[test]
fn a_removed_chain_entry_is_found() {
    let path = temp_db("chaindel");
    honest(&path);
    tamper(&path, "DELETE FROM chain WHERE n = 5");
    let p = problems(&path);
    assert!(p.iter().any(|m| m.contains("missing") || m.contains("does not follow")), "{p:?}");
}

#[test]
fn editing_a_row_and_recomputing_its_entry_still_breaks_the_next_link() {
    // An attacker with the file who changes a result, the entry's payload AND that entry's hash
    // leaves entry 3 pointing at the old hash: the change is still found, at the next link.
    use sha2::{Digest, Sha256};
    let path = temp_db("recompute");
    honest(&path);
    let c = Connection::open(&path).unwrap();
    let (old_payload, prev): (String, String) = c.query_row("SELECT payload, prev FROM chain WHERE n = 2", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert!(old_payload.contains("content"));
    let payload = old_payload.replace("content", "forged");
    let hash: String = Sha256::digest(format!("{prev}\nresult\n{payload}").as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    c.execute("UPDATE results SET result_json = replace(result_json, 'content', 'forged') WHERE seq = 1", []).unwrap();
    c.execute("UPDATE chain SET payload = ?1, hash = ?2 WHERE n = 2", [&payload, &hash]).unwrap();
    drop(c);
    let p = problems(&path);
    assert!(p.len() == 1 && p[0].contains("chain entry 3 does not follow"), "only the next link gives it away: {p:?}");
}

#[test]
fn a_log_cut_short_needs_the_head_kept_elsewhere() {
    let path = temp_db("truncate");
    let log = honest(&path);
    let before = log.verify().unwrap();
    drop(log);
    tamper(&path, "DELETE FROM chain WHERE n > 10; DELETE FROM job_events; DELETE FROM run_events");
    let log = EventLog::open_readonly(&path).unwrap();
    assert!(log.verify().unwrap().ok, "cutting the end off is invisible on its own");
    let r = log.verify_against(Some(&before.head), Some(before.rows)).unwrap();
    assert!(!r.ok && r.problems.iter().any(|m| m.contains("cut short")) && r.problems.iter().any(|m| m.contains("entries but")), "{r:?}");
    assert!(EventLog::open_readonly(&path).unwrap().verify_against(None, None).unwrap().ok);
}

#[test]
fn a_log_without_a_chain_says_so() {
    let path = temp_db("legacy");
    Connection::open(&path).unwrap().execute_batch("CREATE TABLE intents (seq INTEGER PRIMARY KEY, id TEXT);").unwrap();
    let r = EventLog::open_readonly(&path).unwrap().verify().unwrap();
    assert!(!r.ok && r.problems[0].contains("no hash chain"), "{r:?}");
    assert!(EventLog::open_readonly(&path).unwrap().chain_summary().unwrap().is_null());
}

#[test]
fn a_resolved_escalation_is_chained() {
    let path = temp_db("esc");
    honest(&path);
    tamper(&path, "UPDATE escalations SET decision = 'allow'");
    let p = problems(&path);
    assert!(p.iter().any(|m| m.contains("escalations")), "{p:?}");
}
