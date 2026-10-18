//! Seq 15 acceptance: intent and verdict rows are written durably.

use broker::{AutoApprover, Broker};
use eventlog::EventLog;
use intent::{Action, Intent, VerdictKind};
use policy::Policy;
use serde_json::json;
use std::sync::Arc;

fn load_repo_policy() -> Policy {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("policies")
        .join("default.yaml");
    policy::load_from_path(path.to_str().unwrap()).expect("load default.yaml")
}

#[tokio::test]
async fn decide_writes_intent_and_verdict_rows_durably() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("events.db");

    let intent_id: String;
    {
        let broker = Broker::with_file_log(load_repo_policy(), &db, Arc::new(AutoApprover::deny()))
            .expect("open log");
        std::fs::create_dir_all("/tmp/safe").unwrap();
        std::fs::write("/tmp/safe/logging_test.txt", "ok").unwrap();
        let intent = Intent::new(
            Action::ReadFile,
            json!({"path": "/tmp/safe/logging_test.txt"}),
        );
        intent_id = intent.id.clone();

        let v = broker.decide(&intent).await;
        assert!(matches!(v.verdict, VerdictKind::Allow));
    }

    let check = EventLog::open(&db).expect("reopen log");
    assert_eq!(check.count_intents().unwrap(), 1);
    assert_eq!(check.count_verdicts().unwrap(), 1);
    assert_eq!(
        check.latest_verdict_for(&intent_id).unwrap().as_deref(),
        Some("allow"),
    );
}

#[tokio::test]
async fn the_log_records_the_agent_the_broker_assigned_not_one_the_request_claims() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("events.db");
    {
        let broker = Broker::with_file_log(load_repo_policy(), &db, Arc::new(AutoApprover::deny()))
            .expect("open log");
        // A child claims, inside its request, to be the root agent.
        let forged = Intent::new(
            Action::ReadFile,
            json!({ "path": "/tmp/safe/x.txt", "agent": broker::ROOT_AGENT }),
        );
        broker.decide_as("a2", &forged).await;
        broker
            .decide(&Intent::new(
                Action::ReadFile,
                json!({ "path": "/tmp/safe/y.txt" }),
            ))
            .await;
    }
    let out = EventLog::open_readonly(&db).unwrap().export(None).unwrap();
    assert_eq!(out["events"][0]["agent"], "a2");
    assert_eq!(out["events"][1]["agent"], broker::ROOT_AGENT);
}
