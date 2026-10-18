//! The owner's kill switch: one call stops the run at once, whatever the agent has or has not
//! done. Later requests are refused with their own reason (and still logged), the stop is a
//! `kill_switch` run event, and pulling it twice, or after a tripwire, changes nothing.

use broker::{AutoApprover, Broker, KILLED_REASON};
use eventlog::EventLog;
use intent::{Action, Intent, VerdictKind};
use serde_json::json;
use std::sync::Arc;

fn load_repo_policy() -> policy::Policy {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/default.yaml");
    policy::load_from_path(path.to_str().unwrap()).expect("load default.yaml")
}

fn think() -> Intent {
    Intent::new(Action::LlmChat, json!({ "messages": [{ "role": "user", "content": "hi" }] }))
}

#[tokio::test]
async fn the_kill_switch_stops_a_run_with_no_denials_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    let broker = Broker::with_file_log(load_repo_policy(), &db, Arc::new(AutoApprover::deny())).unwrap();
    assert!(!broker.is_halted());

    assert!(broker.kill_switch("test"), "the first pull stops the run");
    assert!(broker.is_halted());
    assert!(!broker.kill_switch("test again"), "a second pull changes nothing");

    let v = broker.decide(&think()).await;
    assert!(matches!(v.verdict, VerdictKind::Deny));
    assert_eq!(v.reason, KILLED_REASON, "the refusal says the owner stopped it");
    drop(broker);

    let doc = EventLog::open_readonly(&db).unwrap().export(None).unwrap();
    assert_eq!(doc["summary"]["intents"], 1, "the refused request is still logged");
    assert_eq!(doc["summary"]["killed_by_owner"], true);
    assert_eq!(doc["summary"]["halted_by_tripwire"], false);
    let stops: Vec<_> = doc["run_events"].as_array().unwrap().iter().filter(|e| e["kind"] == "kill_switch").collect();
    assert_eq!(stops.len(), 1, "exactly one stop is recorded");
}

#[tokio::test]
async fn pulling_it_after_the_tripwire_does_not_record_a_second_stop() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    let broker = Broker::with_file_log(load_repo_policy(), &db, Arc::new(AutoApprover::deny()))
        .unwrap()
        .with_tripwire(1);
    let bad = Intent::new(Action::ReadFile, json!({ "path": "/home/someone/.aws/credentials" }));
    let _ = broker.decide(&bad).await;
    assert!(broker.is_halted());
    assert!(!broker.kill_switch("late"), "already halted");
    drop(broker);
    let doc = EventLog::open_readonly(&db).unwrap().export(None).unwrap();
    assert_eq!(doc["summary"]["killed_by_owner"], false);
}