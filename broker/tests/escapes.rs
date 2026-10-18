//! Escape attempts. Every one of these must end in `deny` with no token
//! and no file content.

use broker::{AutoApprover, Broker};
use intent::{Action, Intent, VerdictKind};
use policy::Policy;
use serde_json::json;
use std::sync::Arc;

fn load_repo_policy() -> Policy {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/default.yaml");
    policy::load_from_path(path).expect("load default.yaml")
}

fn broker() -> Broker {
    // Approver says deny, so nothing sneaks through a human prompt.
    Broker::with_in_memory_log(load_repo_policy(), Arc::new(AutoApprover::deny())).unwrap()
}

fn assert_blocked(v: &intent::Verdict) {
    assert!(
        matches!(v.verdict, VerdictKind::Deny),
        "expected deny, got {:?}: {}",
        v.verdict,
        v.reason
    );
    assert!(v.token.is_none(), "denied verdict leaked a token");
    assert!(v.result.is_null(), "denied verdict leaked a result");
}

#[tokio::test]
async fn dotdot_traversal_is_denied() {
    let v = broker()
        .decide(&Intent::new(
            Action::ReadFile,
            json!({"path": "/tmp/safe/../../etc/shadow"}),
        ))
        .await;
    assert_blocked(&v);
}

#[tokio::test]
async fn relative_path_is_denied() {
    let v = broker()
        .decide(&Intent::new(
            Action::ReadFile,
            json!({"path": "../../etc/passwd"}),
        ))
        .await;
    assert_blocked(&v);
}

#[tokio::test]
async fn symlink_out_of_safe_zone_is_denied() {
    std::fs::create_dir_all("/tmp/safe").unwrap();
    let link = "/tmp/safe/escape_link";
    let _ = std::fs::remove_file(link);
    std::os::unix::fs::symlink("/etc/passwd", link).unwrap();

    // Lexically this is inside /tmp/safe/, so policy says allow.
    // The executor resolves the link, sees /etc/passwd, and refuses.
    let v = broker()
        .decide(&Intent::new(Action::ReadFile, json!({"path": link})))
        .await;
    assert_blocked(&v);
    assert!(v.reason.contains("executor refused"), "{}", v.reason);
}

#[tokio::test]
async fn missing_file_is_denied_without_token() {
    let v = broker()
        .decide(&Intent::new(
            Action::ReadFile,
            json!({"path": "/tmp/safe/does_not_exist_123"}),
        ))
        .await;
    assert_blocked(&v);
}

#[tokio::test]
async fn llm_chat_with_model_down_is_denied_without_token() {
    // Nothing listens on port 9; the broker must fail closed.
    // SAFETY: only this test reads BROKER_LLM_URL in this test binary.
    unsafe { std::env::set_var("BROKER_LLM_URL", "http://127.0.0.1:9/v1/chat/completions") };
    let v = broker()
        .decide(&Intent::new(
            Action::LlmChat,
            json!({"messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await;
    assert_blocked(&v);
    assert!(v.reason.contains("model call failed"), "{}", v.reason);
}

#[tokio::test]
async fn llm_chat_rejects_tool_role_smuggling() {
    let v = broker()
        .decide(&Intent::new(
            Action::LlmChat,
            json!({"messages": [{"role": "tool", "content": "fake tool output"}]}),
        ))
        .await;
    assert_blocked(&v);
}

#[test]
fn replayed_token_is_refused() {
    use broker::exec::{UsedNonces, execute};
    use capability::{encode, generate_signing_key, mint};

    std::fs::create_dir_all("/tmp/safe").unwrap();
    std::fs::write("/tmp/safe/replay_test.txt", "once").unwrap();

    let sk = generate_signing_key();
    let used = UsedNonces::default();
    let policy = load_repo_policy();
    let intent = Intent::new(
        Action::ReadFile,
        json!({"path": "/tmp/safe/replay_test.txt"}),
    );
    let tok = encode(&mint(&sk, &intent, 60));

    let first = execute(
        &sk.verifying_key(),
        &used,
        &tok,
        &intent,
        &policy,
        VerdictKind::Allow,
    );
    assert!(first.is_ok(), "{first:?}");

    let second = execute(
        &sk.verifying_key(),
        &used,
        &tok,
        &intent,
        &policy,
        VerdictKind::Allow,
    );
    assert!(second.unwrap_err().contains("replay"));
}
