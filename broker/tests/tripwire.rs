//! The tripwire halts a run after too many denied requests: later requests
//! are refused (and still logged), and the halt is recorded as a run event.

use broker::{AutoApprover, Broker, HALTED_REASON};
use eventlog::EventLog;
use intent::{Action, Intent, VerdictKind};
use serde_json::json;
use std::sync::Arc;

fn load_repo_policy() -> policy::Policy {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/default.yaml");
    policy::load_from_path(path.to_str().unwrap()).expect("load default.yaml")
}

fn bad() -> Intent {
    Intent::new(
        Action::ReadFile,
        json!({ "path": "/home/someone/.aws/credentials" }),
    )
}

#[tokio::test]
async fn halts_after_the_limit_and_refuses_everything_after() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    let broker = Broker::with_file_log(load_repo_policy(), &db, Arc::new(AutoApprover::deny()))
        .unwrap()
        .with_tripwire(3);

    for _ in 0..2 {
        assert!(matches!(
            broker.decide(&bad()).await.verdict,
            VerdictKind::Deny
        ));
        assert!(!broker.is_halted());
    }
    assert!(matches!(
        broker.decide(&bad()).await.verdict,
        VerdictKind::Deny
    ));
    assert!(broker.is_halted(), "third denial reaches the limit");

    // Even a request the policy would allow is now refused.
    let think = Intent::new(
        Action::LlmChat,
        json!({ "messages": [{ "role": "user", "content": "hi" }] }),
    );
    let v = broker.decide(&think).await;
    assert!(matches!(v.verdict, VerdictKind::Deny));
    assert_eq!(v.reason, HALTED_REASON);
    drop(broker);

    let doc = EventLog::open_readonly(&db).unwrap().export(None).unwrap();
    assert_eq!(
        doc["summary"]["intents"], 4,
        "the refused request is still logged"
    );
    assert_eq!(doc["summary"]["halted_by_tripwire"], true);
    assert_eq!(doc["run_events"][0]["kind"], "tripwire");
}

const WEIGHTED: &str = r#"
rules:
  - name: allow-safe
    action: read_file
    match: { path_prefix: "/tmp/safe/" }
    verdict: allow
  - name: critical-secrets
    action: read_file
    match: { path_prefix: "/tmp/secrets/" }
    verdict: deny
    reason: "never"
    weight: 10
  - name: everyday-miss
    action: read_file
    match: { path_prefix: "/tmp/other/" }
    verdict: deny
    weight: 0
  - name: default-deny
    action: any
    verdict: deny
"#;

fn weighted_broker(limit: u32) -> Broker {
    Broker::with_in_memory_log(
        policy::load_from_str(WEIGHTED).unwrap(),
        Arc::new(AutoApprover::deny()),
    )
    .unwrap()
    .with_tripwire(limit)
}

fn read(path: &str) -> Intent {
    Intent::new(Action::ReadFile, json!({ "path": path }))
}

#[tokio::test]
async fn a_critical_rule_halts_on_its_first_hit() {
    let b = weighted_broker(10);
    b.decide(&read("/tmp/nowhere/a")).await; // weight 1
    assert!(!b.is_halted());
    let v = b.decide(&read("/tmp/secrets/key")).await;
    assert!(matches!(v.verdict, VerdictKind::Deny));
    assert!(b.is_halted(), "weight 10 reaches a limit of 10 at once");
    let after = b.decide(&read("/tmp/safe/x")).await;
    assert_eq!(after.reason, HALTED_REASON);
}

#[tokio::test]
async fn a_zero_weight_rule_never_counts() {
    let b = weighted_broker(3);
    for _ in 0..50 {
        b.decide(&read("/tmp/other/file")).await;
    }
    assert!(!b.is_halted());
}

#[tokio::test]
async fn ordinary_refusals_still_count_one_each() {
    let b = weighted_broker(3);
    for _ in 0..2 {
        b.decide(&read("/tmp/nowhere/a")).await; // default-deny, weight 1
    }
    assert!(!b.is_halted());
    b.decide(&read("/tmp/nowhere/a")).await;
    assert!(b.is_halted());
}

#[tokio::test]
async fn an_executor_refusal_counts_one() {
    // Allowed by policy, refused by the executor (the file does not exist).
    let b = weighted_broker(2);
    b.decide(&read("/tmp/safe/does-not-exist-1")).await;
    assert!(!b.is_halted());
    b.decide(&read("/tmp/safe/does-not-exist-2")).await;
    assert!(b.is_halted());
}

#[tokio::test]
async fn no_tripwire_means_no_halt() {
    let broker =
        Broker::with_in_memory_log(load_repo_policy(), Arc::new(AutoApprover::deny())).unwrap();
    for _ in 0..20 {
        broker.decide(&bad()).await;
    }
    assert!(!broker.is_halted());
}

/// Holds every approval until released, and says when it has been asked.
struct GateApprover {
    asked: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl broker::Approver for GateApprover {
    async fn approve(&self, _: &Intent) -> broker::ApprovalDecision {
        self.asked.notify_one();
        self.release.notified().await;
        broker::ApprovalDecision::Allow
    }
}

#[tokio::test]
async fn a_request_in_flight_when_the_halt_fires_does_not_run() {
    let gate = Arc::new(GateApprover {
        asked: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let broker = Arc::new(
        Broker::with_in_memory_log(load_repo_policy(), gate.clone())
            .unwrap()
            .with_tripwire(1),
    );

    // Needs a human, so it waits at the approval step.
    let waiting = Intent::new(Action::ReadFile, json!({ "path": "/etc/passwd" }));
    let b = Arc::clone(&broker);
    let pending = tokio::spawn(async move { b.decide(&waiting).await });
    gate.asked.notified().await;

    // Another request is denied and trips the wire while the first one waits.
    broker.decide(&bad()).await;
    assert!(broker.is_halted());

    // The human says yes, but the run has halted: nothing may execute.
    gate.release.notify_one();
    let v = pending.await.unwrap();
    assert!(matches!(v.verdict, VerdictKind::Deny), "{v:?}");
    assert_eq!(v.reason, HALTED_REASON);
    assert!(v.token.is_none());
    assert!(v.result.is_null());
}
