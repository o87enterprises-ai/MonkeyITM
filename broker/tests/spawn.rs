//! Starting child agents: off unless both the broker and the policy allow it,
//! root only, group size capped, each child known by its own socket, and the
//! tripwire kills every child.

use broker::spawn::SpawnConfig;
use broker::{AutoApprover, Broker};
use eventlog::EventLog;
use intent::{Action, Intent, Verdict, VerdictKind};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const POLICY: &str = r#"
rules:
  - name: allow-spawn
    action: spawn_agent
    verdict: allow
  - name: allow-send
    action: send_message
    verdict: allow
  - name: allow-recv
    action: recv_message
    verdict: allow
  - name: ask-etc
    action: read_file
    match: { path_prefix: "/etc/" }
    verdict: approve_required
"#;

/// A stand-in child that only waits to be stopped.
fn idle() -> Vec<String> {
    ["sh", "-c", "exec sleep 60"].map(String::from).to_vec()
}

/// A stand-in child that messages its parent through its own socket, then waits.
fn greeter() -> Vec<String> {
    let script = r#"
import json, socket, sys, time, uuid
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
f = s.makefile("rw")
f.write(json.dumps({"id": str(uuid.uuid4()), "action": "send_message",
                    "params": {"to": "a1", "body": "hi from " + sys.argv[2]}}) + "\n")
f.flush()
f.readline()
time.sleep(60)
"#;
    vec!["python3".into(), "-c".into(), script.into()]
}

fn group(dir: &Path, launcher: Vec<String>, max_agents: usize) -> Arc<Broker> {
    let b = Arc::new(
        Broker::with_file_log(
            policy::load_from_str(POLICY).unwrap(),
            dir.join("events.db"),
            Arc::new(AutoApprover::allow()),
        )
        .unwrap(),
    );
    b.enable_spawning(SpawnConfig {
        launcher,
        dir: dir.join("agents"),
        max_agents,
    })
    .unwrap();
    b
}

fn spawn(task: &str) -> Intent {
    Intent::new(Action::SpawnAgent, json!({ "task": task }))
}

fn refused(v: &Verdict, why: &str) {
    assert!(matches!(v.verdict, VerdictKind::Deny), "{v:?}");
    assert!(v.reason.contains(why), "reason was: {}", v.reason);
}

async fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn process_gone(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        // A zombie has already died; it is only waiting to be reaped.
        Ok(stat) => stat
            .rsplit(')')
            .next()
            .is_some_and(|rest| rest.trim_start().starts_with('Z')),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_default_policy_denies_spawning_even_when_the_broker_allows_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/default.yaml");
    let b = Arc::new(
        Broker::with_in_memory_log(
            policy::load_from_path(path.to_str().unwrap()).unwrap(),
            Arc::new(AutoApprover::allow()),
        )
        .unwrap(),
    );
    b.enable_spawning(SpawnConfig {
        launcher: idle(),
        dir: dir.path().join("agents"),
        max_agents: 3,
    })
    .unwrap();
    refused(&b.decide(&spawn("anything")).await, "");
    assert!(b.running_children().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn spawning_is_refused_when_the_broker_was_not_started_with_it() {
    let b = Broker::with_in_memory_log(
        policy::load_from_str(POLICY).unwrap(),
        Arc::new(AutoApprover::allow()),
    )
    .unwrap();
    refused(
        &b.decide(&spawn("anything")).await,
        "not started with spawning enabled",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_directory_is_private_and_must_be_new() {
    let dir = tempfile::tempdir().unwrap();
    let b = group(dir.path(), idle(), 3);
    let mode = std::fs::metadata(dir.path().join("agents"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);

    let again = b.enable_spawning(SpawnConfig {
        launcher: idle(),
        dir: dir.path().join("agents"),
        max_agents: 3,
    });
    assert!(again.is_err(), "an existing directory must be refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_root_spawns_and_the_group_size_is_capped() {
    let dir = tempfile::tempdir().unwrap();
    let b = group(dir.path(), idle(), 3);

    refused(
        &b.decide(&Intent::new(Action::SpawnAgent, json!({}))).await,
        "task",
    );
    let a2 = b.decide(&spawn("one")).await;
    assert_eq!(a2.result, json!({ "agent": "a2" }), "{a2:?}");
    refused(
        &b.decide_as("a2", &spawn("grandchild")).await,
        "only the root agent",
    );
    let a3 = b.decide(&spawn("two")).await;
    assert_eq!(a3.result, json!({ "agent": "a3" }), "{a3:?}");
    refused(&b.decide(&spawn("three")).await, "the limit is 3");
    assert_eq!(b.running_children().len(), 2);
    b.stop_children();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_child_is_known_by_its_socket_and_its_messages_say_so() {
    let dir = tempfile::tempdir().unwrap();
    let b = group(dir.path(), greeter(), 3);
    b.decide(&spawn("say hi")).await;
    b.decide(&spawn("say hi")).await;

    let mut got = Vec::new();
    let start = Instant::now();
    while got.len() < 2 && start.elapsed() < Duration::from_secs(10) {
        let v = b.decide(&Intent::new(Action::RecvMessage, json!({}))).await;
        got.extend(v.result["messages"].as_array().cloned().unwrap_or_default());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    got.sort_by_key(|m| m["from"].as_str().unwrap_or_default().to_string());
    assert_eq!(
        got,
        vec![
            json!({ "from": "a2", "body": "hi from a2" }),
            json!({ "from": "a3", "body": "hi from a3" }),
        ]
    );
    b.stop_children();

    let out = EventLog::open_readonly(dir.path().join("events.db"))
        .unwrap()
        .export(None)
        .unwrap();
    let senders: Vec<_> = out["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "send_message")
        .map(|e| e["agent"].as_str().unwrap().to_string())
        .collect();
    assert!(senders.contains(&"a2".into()) && senders.contains(&"a3".into()));
    let spawned = out["run_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "agent_spawned")
        .count();
    assert_eq!(spawned, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_childs_request_that_needs_a_human_is_denied_without_asking() {
    let dir = tempfile::tempdir().unwrap();
    let b = group(dir.path(), idle(), 3);
    b.decide(&spawn("one")).await;
    let read = Intent::new(Action::ReadFile, json!({ "path": "/etc/hostname" }));
    refused(&b.decide_as("a2", &read).await, "no human approver");
    b.stop_children();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tripwire_kills_every_child() {
    let dir = tempfile::tempdir().unwrap();
    let b = Arc::new(
        Broker::with_file_log(
            policy::load_from_str(POLICY).unwrap(),
            dir.path().join("events.db"),
            Arc::new(AutoApprover::allow()),
        )
        .unwrap()
        .with_tripwire(1),
    );
    b.enable_spawning(SpawnConfig {
        launcher: idle(),
        dir: dir.path().join("agents"),
        max_agents: 3,
    })
    .unwrap();
    b.decide(&spawn("one")).await;
    b.decide(&spawn("two")).await;
    let pids: Vec<u32> = b.running_children().into_iter().map(|(_, p)| p).collect();
    assert_eq!(pids.len(), 2);
    assert!(pids.iter().all(|p| !process_gone(*p)));

    // One child probes its sibling; the refusal trips the wire.
    b.decide_as(
        "a2",
        &Intent::new(Action::SendMessage, json!({ "to": "a3", "body": "psst" })),
    )
    .await;
    assert!(b.is_halted());

    wait_until("both children to be killed", || {
        pids.iter().all(|p| process_gone(*p))
    })
    .await;
    wait_until("both exits to be recorded", || {
        b.running_children().is_empty()
    })
    .await;
    refused(&b.decide(&spawn("three")).await, broker::HALTED_REASON);

    let db = dir.path().join("events.db");
    wait_until("agent_exited events", || {
        let out = EventLog::open_readonly(&db).unwrap().export(None).unwrap();
        out["run_events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| {
                e["kind"] == "agent_exited"
                    && e["detail"]
                        .as_str()
                        .unwrap()
                        .contains("killed by the broker")
            })
            .count()
            == 2
    })
    .await;
    let out = EventLog::open_readonly(&db).unwrap().export(None).unwrap();
    let trip = out["run_events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "tripwire")
        .unwrap();
    assert!(
        trip["detail"]
            .as_str()
            .unwrap()
            .contains("2 child agent(s) killed"),
        "{trip}"
    );
}
