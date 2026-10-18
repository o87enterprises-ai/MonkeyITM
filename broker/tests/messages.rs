//! Messages between agents in one group: routed and logged by the broker,
//! parent and child only, size- and queue-limited, and denied unless policy
//! allows them.

use broker::{AutoApprover, Broker, HALTED_REASON, ROOT_AGENT, group};
use eventlog::EventLog;
use intent::{Action, Intent, Verdict, VerdictKind};
use serde_json::json;
use std::sync::Arc;

const MESSAGING: &str = r#"
rules:
  - name: allow-send
    action: send_message
    verdict: allow
  - name: allow-recv
    action: recv_message
    verdict: allow
"#;

/// Root a1 with two children, a2 and a3.
fn family(policy: &str) -> Broker {
    let b = Broker::with_in_memory_log(
        policy::load_from_str(policy).unwrap(),
        Arc::new(AutoApprover::deny()),
    )
    .unwrap();
    b.register_agent_for_tests("a2", ROOT_AGENT).unwrap();
    b.register_agent_for_tests("a3", ROOT_AGENT).unwrap();
    b
}

fn send(to: &str, body: &str) -> Intent {
    Intent::new(Action::SendMessage, json!({ "to": to, "body": body }))
}

fn recv() -> Intent {
    Intent::new(Action::RecvMessage, json!({}))
}

fn refused(v: &Verdict, why: &str) {
    assert!(matches!(v.verdict, VerdictKind::Deny), "{v:?}");
    assert!(v.reason.contains(why), "reason was: {}", v.reason);
    assert!(v.token.is_none() && v.result.is_null(), "{v:?}");
}

#[tokio::test]
async fn the_default_policy_denies_messaging() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/default.yaml");
    let b = Broker::with_in_memory_log(
        policy::load_from_path(path.to_str().unwrap()).unwrap(),
        Arc::new(AutoApprover::allow()),
    )
    .unwrap();
    b.register_agent_for_tests("a2", ROOT_AGENT).unwrap();
    refused(&b.decide(&send("a2", "hi")).await, "");
    refused(&b.decide_as("a2", &recv()).await, "");
}

#[tokio::test]
async fn parent_to_child_is_delivered_once_with_the_true_sender() {
    let b = family(MESSAGING);
    let v = b.decide(&send("a2", "do task 4")).await;
    assert!(matches!(v.verdict, VerdictKind::Allow), "{v:?}");

    // a3 gets nothing: the message was for a2.
    let other = b.decide_as("a3", &recv()).await;
    assert_eq!(other.result["messages"], json!([]));

    let got = b.decide_as("a2", &recv()).await;
    assert_eq!(
        got.result["messages"],
        json!([{ "from": "a1", "body": "do task 4" }])
    );
    let again = b.decide_as("a2", &recv()).await;
    assert_eq!(again.result["messages"], json!([]));
}

#[tokio::test]
async fn child_to_parent_is_delivered() {
    let b = family(MESSAGING);
    assert!(matches!(
        b.decide_as("a3", &send(ROOT_AGENT, "done")).await.verdict,
        VerdictKind::Allow
    ));
    let got = b.decide(&recv()).await;
    assert_eq!(got.result["messages"][0]["from"], "a3");
}

#[tokio::test]
async fn children_cannot_message_each_other() {
    let b = family(MESSAGING);
    refused(
        &b.decide_as("a2", &send("a3", "psst")).await,
        "only their parent or their own children",
    );
    let got = b.decide_as("a3", &recv()).await;
    assert_eq!(got.result["messages"], json!([]));
}

#[tokio::test]
async fn bad_targets_and_bodies_are_refused() {
    let b = family(MESSAGING);
    refused(&b.decide(&send("a9", "x")).await, "no agent a9");
    refused(
        &b.decide(&send(ROOT_AGENT, "x")).await,
        "cannot message itself",
    );
    let big = "x".repeat(group::MAX_MESSAGE_BYTES + 1);
    refused(&b.decide(&send("a2", &big)).await, "the limit is");
    refused(
        &b.decide(&Intent::new(Action::SendMessage, json!({ "to": "a2" })))
            .await,
        "needs a string `body`",
    );
}

#[tokio::test]
async fn a_full_mailbox_refuses_more_until_it_is_read() {
    let b = family(MESSAGING);
    for i in 0..group::MAX_QUEUED {
        let v = b.decide(&send("a2", &format!("m{i}"))).await;
        assert!(
            matches!(v.verdict, VerdictKind::Allow),
            "message {i}: {v:?}"
        );
    }
    refused(
        &b.decide(&send("a2", "one too many")).await,
        "unread messages",
    );

    let first = b.decide_as("a2", &recv()).await;
    assert_eq!(
        first.result["messages"].as_array().unwrap().len(),
        group::MAX_PER_RECV
    );
    assert_eq!(
        first.result["remaining"],
        group::MAX_QUEUED - group::MAX_PER_RECV
    );
    assert!(matches!(
        b.decide(&send("a2", "room again")).await.verdict,
        VerdictKind::Allow
    ));
}

#[tokio::test]
async fn nothing_is_delivered_after_a_halt() {
    let b = family(MESSAGING).with_tripwire(1);
    // A child probing its sibling is refused, and that trips the wire.
    b.decide_as("a2", &send("a3", "psst")).await;
    assert!(b.is_halted());
    refused(&b.decide(&send("a2", "carry on")).await, HALTED_REASON);
    refused(&b.decide_as("a2", &recv()).await, HALTED_REASON);
}

#[tokio::test]
async fn messages_are_logged_with_the_sending_agent() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    {
        let b = Broker::with_file_log(
            policy::load_from_str(MESSAGING).unwrap(),
            &db,
            Arc::new(AutoApprover::deny()),
        )
        .unwrap();
        b.register_agent_for_tests("a2", ROOT_AGENT).unwrap();
        b.decide(&send("a2", "hello")).await;
        b.decide_as("a2", &recv()).await;
    }
    let out = EventLog::open_readonly(&db).unwrap().export(None).unwrap();
    let ev = &out["events"];
    assert_eq!(ev[0]["agent"], ROOT_AGENT);
    assert_eq!(ev[0]["action"], "send_message");
    assert_eq!(ev[0]["params"]["body"], "hello");
    assert_eq!(ev[1]["agent"], "a2");
    assert_eq!(ev[1]["action"], "recv_message");
    assert_eq!(ev[1]["final_verdict"], "allow");
}
