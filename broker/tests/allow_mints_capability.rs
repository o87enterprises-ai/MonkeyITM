//! Capability token tests. Seq 14 property: on `allow`, mint a token bound to
//! the intent and verifiable against the broker's pubkey. Seq 16 changes:
//! `approve_required` is no longer terminal — it is resolved by the approver.

use broker::{AutoApprover, Broker, TOKEN_TTL_SECS};
use capability::{decode, verify};
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
async fn allow_mints_verifiable_capability() {
    let broker = broker_with(AutoApprover::deny()); // never consulted for this path
    let vk = broker.verifying_key();

    std::fs::create_dir_all("/tmp/safe").unwrap();
    std::fs::write("/tmp/safe/mint_test.txt", "hello from the safe zone").unwrap();

    let intent = Intent::new(Action::ReadFile, json!({"path": "/tmp/safe/mint_test.txt"}));
    let verdict = broker.decide(&intent).await;

    assert!(
        matches!(verdict.verdict, VerdictKind::Allow),
        "{}",
        verdict.reason
    );
    assert_eq!(verdict.result["content"], "hello from the safe zone");

    let wire = verdict.token.expect("allow verdict must carry a token");
    let tok = decode(&wire).expect("token decodes from base64");
    verify(&vk, &tok, Some(&intent)).expect("token verifies against broker pubkey");

    assert_eq!(tok.payload.intent_id, intent.id);
    assert_eq!(tok.payload.action, "read_file");
    assert!(!tok.payload.nonce.is_empty());

    let ttl = tok.payload.expires_at - tok.payload.issued_at;
    assert_eq!(ttl, TOKEN_TTL_SECS);
}

#[tokio::test]
async fn policy_deny_does_not_mint_token() {
    let broker = broker_with(AutoApprover::allow()); // never consulted
    let intent = Intent::new(Action::Exec, json!({"cmd": "ls"}));
    let verdict = broker.decide(&intent).await;

    assert!(matches!(verdict.verdict, VerdictKind::Deny));
    assert!(verdict.token.is_none());
}

#[tokio::test]
async fn approve_required_denied_by_human_returns_deny_without_token() {
    let broker = broker_with(AutoApprover::deny());
    let intent = Intent::new(Action::ReadFile, json!({"path": "/etc/passwd"}));
    let verdict = broker.decide(&intent).await;

    assert!(matches!(verdict.verdict, VerdictKind::Deny));
    assert_eq!(verdict.reason, "denied by human");
    assert!(verdict.token.is_none());
}

#[tokio::test]
async fn approve_required_allowed_by_human_returns_allow_with_token() {
    let broker = broker_with(AutoApprover::allow());
    let vk = broker.verifying_key();
    let intent = Intent::new(Action::ReadFile, json!({"path": "/etc/passwd"}));
    let verdict = broker.decide(&intent).await;

    assert!(matches!(verdict.verdict, VerdictKind::Allow));
    assert_eq!(verdict.reason, "approved by human");

    let wire = verdict.token.expect("allow verdict must carry a token");
    let tok = decode(&wire).expect("token decodes");
    verify(&vk, &tok, Some(&intent)).expect("token verifies");
}
