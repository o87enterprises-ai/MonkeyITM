//! Seq 16 acceptance: `approve_required` writes an escalation row, asks the
//! approver, records the human's answer, and returns the resolved verdict.

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

fn broker_with(approver: AutoApprover) -> Broker {
    Broker::with_in_memory_log(load_repo_policy(), Arc::new(approver)).expect("in-memory log")
}

#[tokio::test]
async fn human_approves_then_verdict_is_allow_and_escalation_recorded() {
    let broker = broker_with(AutoApprover::allow());
    let intent = Intent::new(Action::ReadFile, json!({"path": "/etc/passwd"}));
    let v = broker.decide(&intent).await;

    assert!(matches!(v.verdict, VerdictKind::Allow));
    assert_eq!(v.reason, "approved by human");
    assert!(v.token.is_some(), "human-approved allow must carry a token");
}

#[tokio::test]
async fn human_denies_then_verdict_is_deny_without_token() {
    let broker = broker_with(AutoApprover::deny());
    let intent = Intent::new(Action::ReadFile, json!({"path": "/etc/passwd"}));
    let v = broker.decide(&intent).await;

    assert!(matches!(v.verdict, VerdictKind::Deny));
    assert_eq!(v.reason, "denied by human");
    assert!(v.token.is_none());
}

#[tokio::test]
async fn escalation_row_is_written_and_resolved() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("events.db");

    let intent = Intent::new(Action::ReadFile, json!({"path": "/etc/passwd"}));
    let intent_id = intent.id.clone();

    {
        let broker =
            Broker::with_file_log(load_repo_policy(), &db, Arc::new(AutoApprover::allow()))
                .expect("open log");
        let v = broker.decide(&intent).await;
        assert!(matches!(v.verdict, VerdictKind::Allow));
    }

    let check = EventLog::open(&db).expect("reopen");
    assert_eq!(check.count_escalations().unwrap(), 1);
    assert_eq!(check.pending_escalation_count().unwrap(), 0);
    assert_eq!(
        check
            .latest_escalation_decision(&intent_id)
            .unwrap()
            .as_deref(),
        Some("allow"),
    );
}

#[tokio::test]
async fn non_escalating_intent_writes_no_escalation_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("events.db");

    {
        let broker =
            Broker::with_file_log(load_repo_policy(), &db, Arc::new(AutoApprover::allow()))
                .expect("open log");
        // /tmp/safe is an unconditional allow — approver is never consulted.
        std::fs::create_dir_all("/tmp/safe").unwrap();
        std::fs::write("/tmp/safe/approval_test.txt", "ok").unwrap();
        let intent = Intent::new(
            Action::ReadFile,
            json!({"path": "/tmp/safe/approval_test.txt"}),
        );
        let v = broker.decide(&intent).await;
        assert!(matches!(v.verdict, VerdictKind::Allow));
    }

    let check = EventLog::open(&db).expect("reopen");
    assert_eq!(check.count_escalations().unwrap(), 0);
}

#[tokio::test]
async fn unattended_run_denies_escalations_and_records_them_as_unattended() {
    let broker =
        Broker::with_in_memory_log(load_repo_policy(), Arc::new(broker::UnattendedApprover))
            .expect("in-memory log");
    let intent = Intent::new(Action::ReadFile, json!({"path": "/etc/passwd"}));
    let v = broker.decide(&intent).await;

    assert!(matches!(v.verdict, VerdictKind::Deny));
    assert_eq!(v.reason, "no human approver (unattended run)");
    assert!(v.token.is_none());
}
