//! Broker library surface.
//!
//! `main.rs` is a thin entry point. Everything decision-shaped lives here so
//! integration tests can drive it without a Unix socket.
//!
//! Decision flow inside `Broker::decide`:
//!   1. Write the intent row **before** the policy decision.
//!   2. Evaluate the policy.
//!   3. If `approve_required`, write an escalation row, ask the approver,
//!      write the human's answer back on the escalation row, and convert the
//!      verdict to `allow` or `deny` accordingly.
//!   4. On `allow`, mint a capability token.
//!   5. Hand the token to the executor, which verifies it, re-checks the
//!      canonical path against policy, and performs the action. Any executor
//!      failure turns the verdict into `deny` and drops the token.
//!   6. Write the verdict row (including the result).
//!
//! If any log write fails, the broker fails closed: the caller receives
//! `deny` with a `log failure` reason and no token is ever released.

pub mod banner;
pub mod exec;
pub mod export;
pub mod verify;
pub mod group;
pub mod spawn;
pub mod stage;
pub mod web;
pub mod workbench;

use async_trait::async_trait;
use capability::ed25519_dalek::{SigningKey, VerifyingKey};
use capability::{encode, generate_signing_key, mint};
use eventlog::EventLog;
use intent::{Action, Intent, Verdict, VerdictKind};
use policy::Policy;
use serde_json::Value;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub const SOCK_PATH: &str = "/tmp/broker.sock";

/// Where the root agent's socket lives: `BROKER_SOCKET` if set (so several
/// brokers can run on one host, one per group), else `SOCK_PATH`.
fn sock_path() -> String {
    std::env::var("BROKER_SOCKET").unwrap_or_else(|_| SOCK_PATH.to_string())
}
pub const DEFAULT_POLICY_PATH: &str = "policies/default.yaml";
pub const DEFAULT_LOG_PATH: &str = "broker.db";

/// Reason given for every intent once the tripwire has halted the run.
pub use eventlog::ROOT_AGENT;

pub const HALTED_REASON: &str = "run halted by tripwire: too many denied requests";

/// Reason given for every intent once the owner has pulled the kill switch.
pub const KILLED_REASON: &str = "run stopped by the owner (kill switch)";

/// Capability token lifetime. Matches the handoff's 60s.
pub const TOKEN_TTL_SECS: i64 = 60;

// ---- Approver -----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Allow,
    Deny,
    /// No human is present (benchmark runs). Treated as deny, recorded
    /// separately so it counts as a boundary attempt.
    Unattended,
}

/// Anything that can answer "may I?" for a single intent. Real code uses
/// `StdinApprover`; tests use `AutoApprover`.
#[async_trait]
pub trait Approver: Send + Sync {
    async fn approve(&self, intent: &Intent) -> ApprovalDecision;
}

/// A deterministic approver for tests. Returns the same answer every time.
pub struct AutoApprover(pub ApprovalDecision);

impl AutoApprover {
    pub fn allow() -> Self {
        Self(ApprovalDecision::Allow)
    }
    pub fn deny() -> Self {
        Self(ApprovalDecision::Deny)
    }
}

#[async_trait]
impl Approver for AutoApprover {
    async fn approve(&self, _intent: &Intent) -> ApprovalDecision {
        self.0
    }
}

/// For unattended runs: every escalation is denied and recorded as such.
pub struct UnattendedApprover;

#[async_trait]
impl Approver for UnattendedApprover {
    async fn approve(&self, _intent: &Intent) -> ApprovalDecision {
        ApprovalDecision::Unattended
    }
}

/// On a terminal, drop anything typed before the question is shown, so a
/// stray keypress (or a "y" typed for an earlier prompt) cannot answer a
/// question the human has not seen. Piped input is left alone: there the
/// answers are a script, read in order.
fn discard_type_ahead() {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        // SAFETY: tcflush on fd 0 only discards queued input; no memory is touched.
        unsafe {
            libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
        }
    }
}

/// Reads y/n from stdin. Prints the intent and prompt to stderr so the agent
/// (which never sees the broker's stderr) is not confused with the question.
pub struct StdinApprover;

#[async_trait]
impl Approver for StdinApprover {
    async fn approve(&self, intent: &Intent) -> ApprovalDecision {
        use std::io::Write;

        eprintln!();
        eprintln!("=================================================");
        eprintln!("  {}", crate::banner::approval_header());
        eprintln!("-------------------------------------------------");
        eprintln!("  intent_id:     {}", intent.id);
        eprintln!("  action:        {:?}", intent.action);
        eprintln!("  params:        {}", intent.params);
        eprintln!("  justification: {}", intent.justification);
        eprintln!("=================================================");
        discard_type_ahead();
        eprint!("  approve? [y/N]: ");
        let _ = std::io::stderr().flush();

        // std's stdin keeps one shared buffer for the whole process, so answers
        // that arrive together (piped or pasted) are not lost between prompts.
        let read = tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).map(|_| line)
        })
        .await;
        match read {
            Ok(Ok(line)) => {
                let ans = line.trim().to_ascii_lowercase();
                if ans == "y" || ans == "yes" {
                    ApprovalDecision::Allow
                } else {
                    ApprovalDecision::Deny
                }
            }
            Ok(Err(e)) => {
                eprintln!("broker: stdin read failed ({e}); defaulting to deny");
                ApprovalDecision::Deny
            }
            Err(e) => {
                eprintln!("broker: stdin read task failed ({e}); defaulting to deny");
                ApprovalDecision::Deny
            }
        }
    }
}

// ---- Broker -------------------------------------------------------------

pub struct Broker {
    pub policy: Arc<Policy>,
    signing_key: SigningKey,
    log: Mutex<EventLog>,
    approver: Arc<dyn Approver>,
    used_nonces: Arc<exec::UsedNonces>,
    /// Halt the run after this many denied requests (None = never).
    tripwire: Option<u32>,
    denials: AtomicU32,
    halted: AtomicBool,
    /// Set when the owner pulled the kill switch (rather than the tripwire firing).
    killed: AtomicBool,
    group: Mutex<group::Group>,
    spawner: OnceLock<Arc<spawn::Spawner>>,
}

impl Broker {
    pub fn new(policy: Policy, log: EventLog, approver: Arc<dyn Approver>) -> Self {
        Self {
            policy: Arc::new(policy),
            signing_key: generate_signing_key(),
            log: Mutex::new(log),
            approver,
            used_nonces: Arc::new(Default::default()),
            tripwire: None,
            denials: AtomicU32::new(0),
            halted: AtomicBool::new(false),
            killed: AtomicBool::new(false),
            group: Mutex::new(group::Group::default()),
            spawner: OnceLock::new(),
        }
    }

    /// Let the root agent start children (policy must still allow `spawn_agent`).
    pub fn enable_spawning(self: &Arc<Self>, cfg: spawn::SpawnConfig) -> std::io::Result<()> {
        let s = spawn::Spawner::new(cfg, Arc::downgrade(self))?;
        self.spawner
            .set(Arc::new(s))
            .map_err(|_| std::io::Error::other("spawning is already enabled"))
    }

    /// Child agents still running, as (agent id, process group id).
    pub fn running_children(&self) -> Vec<(String, u32)> {
        self.spawner.get().map(|s| s.running()).unwrap_or_default()
    }

    /// Kill every running child agent. Returns how many were running.
    pub fn stop_children(&self) -> usize {
        self.spawner.get().map(|s| s.kill_all()).unwrap_or(0)
    }

    fn run_event(&self, kind: &str, detail: &str) {
        let log = self.log.lock().expect("log mutex poisoned");
        if let Err(e) = log.record_run_event(kind, detail) {
            eprintln!("broker: LOG FAILURE recording {kind}: {e}");
        }
    }

    /// Add `id` to the group as a child of `parent`. **Internal and test use
    /// only**: this bypasses the group size cap that `spawn_agent` enforces.
    /// The production path is `Spawner::spawn_inner`.
    #[doc(hidden)]
    pub fn register_agent_for_tests(&self, id: &str, parent: &str) -> Result<(), String> {
        self.group
            .lock()
            .expect("group mutex poisoned")
            .add(id, parent)
    }

    /// Stop the run automatically once `limit` requests have been denied:
    /// every later request is refused, the halt is logged, and the benchmark
    /// workbench (if any) is killed. Detection that doesn't stop anything
    /// isn't containment.
    pub fn with_tripwire(mut self, limit: u32) -> Self {
        self.tripwire = (limit > 0).then_some(limit);
        self
    }

    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    pub fn with_in_memory_log(
        policy: Policy,
        approver: Arc<dyn Approver>,
    ) -> eventlog::rusqlite::Result<Self> {
        Ok(Self::new(policy, EventLog::in_memory()?, approver))
    }

    pub fn with_file_log(
        policy: Policy,
        path: impl AsRef<Path>,
        approver: Arc<dyn Approver>,
    ) -> eventlog::rusqlite::Result<Self> {
        Ok(Self::new(policy, EventLog::open(path)?, approver))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Decide for the root agent (single-agent runs).
    pub async fn decide(&self, intent: &Intent) -> Verdict {
        self.decide_as(ROOT_AGENT, intent).await
    }

    /// Decide for `agent`, which the caller knows from the socket the intent
    /// arrived on. Nothing inside the intent can change it.
    pub async fn decide_as(&self, agent: &str, intent: &Intent) -> Verdict {
        // 1. Intent row first.
        {
            let log = self.log.lock().expect("log mutex poisoned");
            if let Err(e) = log.record_intent_as(agent, intent) {
                eprintln!("broker: LOG FAILURE recording intent {}: {e}", intent.id);
                return deny(intent.id.clone(), format!("log failure: {e}"));
            }
        }

        // 1b. A halted run refuses everything, but still logs what was asked.
        if self.is_halted() {
            let reason = if self.killed.load(Ordering::SeqCst) { KILLED_REASON } else { HALTED_REASON };
            let v = deny(intent.id.clone(), reason.to_string());
            let log = self.log.lock().expect("log mutex poisoned");
            if let Err(e) = log.record_verdict(&v) {
                eprintln!("broker: LOG FAILURE recording verdict for {}: {e}", v.id);
            }
            return v;
        }

        // 2. Policy decision. `weight` is what a refusal here counts toward the tripwire.
        let (mut v, weight) = self.policy.decide_weighted(intent);
        let policy_kind = v.verdict;

        // 2b. Approval loop.
        if matches!(v.verdict, VerdictKind::ApproveRequired) {
            {
                let log = self.log.lock().expect("log mutex poisoned");
                if let Err(e) = log.record_escalation_requested(&intent.id) {
                    eprintln!(
                        "broker: LOG FAILURE recording escalation for {}: {e}",
                        intent.id
                    );
                    return deny(intent.id.clone(), format!("log failure: {e}"));
                }
            }

            // Only the root agent's requests reach a human; children run unattended.
            let decision = if agent == ROOT_AGENT {
                self.approver.approve(intent).await
            } else {
                ApprovalDecision::Unattended
            };
            let (kind, reason, decision_str) = match decision {
                ApprovalDecision::Allow => (VerdictKind::Allow, "approved by human", "allow"),
                ApprovalDecision::Deny => (VerdictKind::Deny, "denied by human", "deny"),
                ApprovalDecision::Unattended => (
                    VerdictKind::Deny,
                    "no human approver (unattended run)",
                    "unattended",
                ),
            };

            {
                let log = self.log.lock().expect("log mutex poisoned");
                if let Err(e) = log.resolve_escalation(&intent.id, decision_str) {
                    eprintln!(
                        "broker: LOG FAILURE resolving escalation for {}: {e}",
                        intent.id
                    );
                    return deny(intent.id.clone(), format!("log failure: {e}"));
                }
            }

            v.verdict = kind;
            v.reason = reason.to_string();
        }

        // 2c. The halt can fire while this request is being decided (another
        // connection's denial, or a slow human). Nothing runs after a halt.
        if matches!(v.verdict, VerdictKind::Allow) && self.is_halted() {
            v.verdict = VerdictKind::Deny;
            v.reason = HALTED_REASON.to_string();
        }

        // 3. On allow, run the action. Only the executor gets a capability
        // token: group actions are carried out by the broker itself, and
        // there is no nonce for a token to consume.
        if matches!(v.verdict, VerdictKind::Allow) {
            let (outcome, wire): (Result<Value, String>, Option<String>) =
                if intent.action == Action::SpawnAgent {
                    let r: Result<Value, String> = match self.spawner.get() {
                        Some(s) => s.spawn(agent, intent).await,
                        None => Err(
                            "this broker was not started with spawning enabled (BROKER_MAX_AGENTS)"
                                .into(),
                        ),
                    };
                    (r, None)
                } else if group::is_routed(intent.action) {
                    let r = self
                        .group
                        .lock()
                        .expect("group mutex poisoned")
                        .route(agent, intent);
                    (r, None)
                } else {
                    let tok = mint(&self.signing_key, intent, TOKEN_TTL_SECS);
                    let wire = encode(&tok);
                    let (vk, used, policy, owned, tok_str) = (
                        self.verifying_key(),
                        Arc::clone(&self.used_nonces),
                        Arc::clone(&self.policy),
                        intent.clone(),
                        wire.clone(),
                    );
                    let r = tokio::task::spawn_blocking(move || {
                        exec::execute(&vk, &used, &tok_str, &owned, &policy, policy_kind)
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("executor panicked: {e}")));
                    (r, Some(wire))
                };
            match outcome {
                Ok(result) => {
                    let view = exec::log_view(intent, &result);
                    let log = self.log.lock().expect("log mutex poisoned");
                    let result_err = log.record_result(&intent.id, &view).err();
                    drop(log);
                    if let Some(e) = result_err {
                        eprintln!(
                            "broker: LOG FAILURE recording result for {}: {e}",
                            intent.id
                        );
                        // The action has already run; the world changed. Do not
                        // return here: fall through so the verdict row and the
                        // tripwire count still see a deny.
                        v.verdict = VerdictKind::Deny;
                        v.reason = format!("log failure after the action ran: {e}");
                        v.result = serde_json::Value::Null;
                        v.token = None;
                    } else {
                        v.result = result;
                        v.token = wire;
                    }
                }
                Err(why) => {
                    v.verdict = VerdictKind::Deny;
                    v.reason = format!("executor refused: {why}");
                    v.result = serde_json::Value::Null;
                    v.token = None;
                }
            }
        }

        // 4. Verdict row.
        {
            let log = self.log.lock().expect("log mutex poisoned");
            if let Err(e) = log.record_verdict(&v) {
                eprintln!("broker: LOG FAILURE recording verdict for {}: {e}", v.id);
                drop(log);
                // Fail closed for the agent, and still count the denial: a
                // denial that cannot be logged must not raise the tripwire
                // limit. Drop the log guard first - count_denial re-locks it.
                self.count_denial_by(weight);
                return deny(v.id, format!("log failure: {e}"));
            }
        }

        // 5. Tripwire. A refusal by the policy counts its rule's weight; a refusal by
        // the executor (a missing file, a bad parameter, the group cap) counts 1.
        if matches!(v.verdict, VerdictKind::Deny) {
            let refused_by_rule =
                !matches!(policy_kind, VerdictKind::Allow) && v.reason != HALTED_REASON;
            self.count_denial_by(if refused_by_rule { weight } else { 1 });
        }

        v
    }

    /// A line that is not a request at all (too long, or not a valid intent).
    /// The agent never sends one, so it is either a fault or probing: it is
    /// logged as a run event and counts toward the tripwire like a denial,
    /// so garbage cannot be sent forever without a trace or a halt.
    fn malformed(&self, agent: &str, why: &str) {
        let why: String = why.chars().take(200).collect();
        self.run_event(
            "malformed_request",
            &serde_json::json!({ "agent": agent, "reason": why }).to_string(),
        );
        self.count_denial();
    }

    fn count_denial(&self) {
        self.count_denial_by(1);
    }

    fn count_denial_by(&self, weight: u32) {
        let Some(limit) = self.tripwire else { return };
        if weight == 0 {
            return;
        }
        let n = self
            .denials
            .fetch_add(weight, Ordering::SeqCst)
            .saturating_add(weight);
        if n < limit || self.is_halted() {
            return;
        }
        let detail = format!(
            "{n} denied requests reached the tripwire limit of {limit}; all further requests refused"
        );
        eprintln!("broker: TRIPWIRE: {detail}");
        self.stop_everything("tripwire", detail);
    }

    /// The owner stops the run now, whatever the agent is doing: every later request is
    /// refused, the workbench container and every child agent are killed, and the stop is
    /// logged as a `kill_switch` run event. Safe to call more than once and from any thread;
    /// returns false when the run was already halted. Nothing the agent sends can reach this.
    pub fn kill_switch(&self, who: &str) -> bool {
        self.killed.store(true, Ordering::SeqCst);
        eprintln!("broker: KILL SWITCH pulled by {who}");
        self.stop_everything("kill_switch", format!("stopped by the owner ({who}); all further requests refused"))
    }

    fn stop_everything(&self, kind: &str, detail: String) -> bool {
        if self.halted.swap(true, Ordering::SeqCst) {
            return false;
        }
        let killed = workbench::Workbench::from_env().map(|wb| wb.kill());
        let mut detail = match killed {
            Some(Ok(())) => format!("{detail}; workbench container killed"),
            Some(Err(e)) => format!("{detail}; killing the workbench failed: {e}"),
            None => detail,
        };
        let children = self.stop_children();
        if children > 0 {
            detail = format!("{detail}; {children} child agent(s) killed");
        }
        let log = self.log.lock().expect("log mutex poisoned");
        if let Err(e) = log.record_run_event(kind, &detail) {
            eprintln!("broker: LOG FAILURE recording {kind}: {e}");
        }
        true
    }
}

fn deny(id: String, reason: String) -> Verdict {
    Verdict {
        id,
        verdict: VerdictKind::Deny,
        result: serde_json::Value::Null,
        reason,
        token: None,
    }
}

// ---- Server -------------------------------------------------------------

pub async fn run_server(policy: Policy) -> std::io::Result<()> {
    let log_path = std::env::var("BROKER_LOG").unwrap_or_else(|_| DEFAULT_LOG_PATH.to_string());

    let unattended = std::env::var("BROKER_UNATTENDED").is_ok_and(|v| v == "1");
    // Answers from a pipe come from a script, in order, and cannot be matched to the question they answer
    // (type-ahead cannot be discarded on a pipe). So a piped stdin denies escalations unless the operator
    // opts in with BROKER_ALLOW_PIPED_APPROVAL=1.
    let piped = {
        use std::io::IsTerminal;
        !std::io::stdin().is_terminal()
    };
    let allow_piped = std::env::var("BROKER_ALLOW_PIPED_APPROVAL").is_ok_and(|v| v == "1");
    let approver: Arc<dyn Approver> = if unattended {
        eprintln!("broker: unattended mode: escalations are denied and counted");
        Arc::new(UnattendedApprover)
    } else if piped && !allow_piped {
        eprintln!(
            "broker: stdin is not a terminal: escalations are denied and counted \
             (set BROKER_ALLOW_PIPED_APPROVAL=1 to take answers from a script)"
        );
        Arc::new(UnattendedApprover)
    } else {
        Arc::new(StdinApprover)
    };
    if let Some(c) = std::env::var("BROKER_WORKBENCH")
        .ok()
        .filter(|s| !s.is_empty())
    {
        match workbench::Workbench::from_env() {
            Some(_) => {
                eprintln!("broker: workbench container {c}, /workspace -> $BROKER_WORKBENCH_DIR")
            }
            None => {
                return Err(std::io::Error::other(
                    "BROKER_WORKBENCH is set but BROKER_WORKBENCH_DIR is missing or unreadable",
                ));
            }
        }
    }
    let tripwire = std::env::var("BROKER_TRIPWIRE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let broker = Arc::new(
        Broker::with_file_log(policy, &log_path, approver)
            .map_err(|e| std::io::Error::other(format!("failed to open log at {log_path}: {e}")))?
            .with_tripwire(tripwire),
    );
    if tripwire > 0 {
        eprintln!("broker: tripwire armed: the run halts after {tripwire} denied requests");
    }
    eprintln!("broker: log at {log_path}");

    let max_agents = std::env::var("BROKER_MAX_AGENTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);
    if max_agents > 1 {
        let dir = std::env::var("BROKER_AGENT_DIR")
            .unwrap_or_else(|_| format!("/tmp/broker-agents-{}", std::process::id()));
        let launcher = std::env::var("BROKER_CHILD_LAUNCHER")
            .unwrap_or_else(|_| "scripts/run-child.sh".to_string());
        broker
            .enable_spawning(spawn::SpawnConfig {
                launcher: vec![launcher],
                dir: dir.clone().into(),
                max_agents,
            })
            .map_err(|e| std::io::Error::other(format!("cannot enable spawning in {dir}: {e}")))?;
        eprintln!("broker: spawning enabled: up to {max_agents} agents, child sockets in {dir}");
    }

    let sock_path = sock_path();
    let _ = std::fs::remove_file(&sock_path);
    let listener = bind_private(std::path::Path::new(&sock_path))?;
    eprintln!("broker: listening on {sock_path}");

    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    // The owner's kill switch: SIGUSR1, or a file appearing at BROKER_KILL_FILE (default: the log
    // path plus ".KILL"). Either one stops the agents at once and keeps the broker up to log it.
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let kill_file = std::env::var("BROKER_KILL_FILE").unwrap_or_else(|_| format!("{log_path}.KILL"));
    let _ = std::fs::remove_file(&kill_file); // a leftover file from an earlier run must not stop this one
    eprintln!("broker: kill switch: SIGUSR1, or create {kill_file}");
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let b = Arc::clone(&broker);
                        tokio::spawn(async move {
                            if let Err(e) = handle(stream, b, ROOT_AGENT.to_string()).await {
                                eprintln!("broker: connection error: {e}");
                            }
                        });
                    }
                    Err(e) => eprintln!("broker: accept error: {e}"),
                }
            }
            _ = sigusr1.recv() => { broker.kill_switch("SIGUSR1"); }
            _ = tick.tick() => {
                if !broker.is_halted() && std::path::Path::new(&kill_file).exists() {
                    broker.kill_switch("kill file");
                }
            }
            // Ctrl-C, `kill` (SIGTERM, also what service managers and container
            // runtimes send) and a closed terminal (SIGHUP) all stop the group.
            _ = tokio::signal::ctrl_c() => return shutdown(&broker, &sock_path, "SIGINT").await,
            _ = sigterm.recv() => return shutdown(&broker, &sock_path, "SIGTERM").await,
            _ = sighup.recv() => return shutdown(&broker, &sock_path, "SIGHUP").await,
        }
    }
}

/// Kill every child, then wait (up to 5 s) for each one's exit to be recorded,
/// so a clean stop leaves an `agent_exited` row for every child.
async fn shutdown(broker: &Broker, sock_path: &str, why: &str) -> std::io::Result<()> {
    eprintln!("broker: shutdown ({why})");
    let n = broker.stop_children();
    if n > 0 {
        eprintln!("broker: killed {n} child agent(s)");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !broker.running_children().is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // A waiter leaves the running list just before it writes the exit row.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    broker.run_event(
        "shutdown",
        &serde_json::json!({ "signal": why, "children_killed": n }).to_string(),
    );
    let _ = std::fs::remove_file(sock_path);
    Ok(())
}

/// Bind a Unix socket that only the broker's own user can connect to (mode
/// 0600), whatever umask the broker was started with. The socket is created
/// inside a fresh directory that only this user can enter, made 0600 there,
/// and only then renamed to `path`, so it is never connectable by others,
/// even briefly. (Changing the umask instead would affect every thread.)
pub(crate) fn bind_private(path: &std::path::Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    // Kept short: a Unix socket path is limited to about 107 bytes, and the socket
    // sits one directory deeper than `path` while it is staged.
    let staging = parent.join(format!(".b{:x}{:x}", std::process::id(), nonce & 0xffff_ffff));
    std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let result = (|| {
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;
        let inner = staging.join("sock");
        let listener = UnixListener::bind(&inner)?;
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&inner, path)?;
        Ok(listener)
    })();
    let _ = std::fs::remove_file(staging.join("sock"));
    let _ = std::fs::remove_dir(&staging);
    result
}

/// Largest intent line the broker reads; a longer line is refused unparsed.
/// Set above the 1 MB write_file limit (JSON escaping can grow content) so
/// oversized writes still reach the executor and are logged as refusals.
pub const MAX_INTENT_BYTES: usize = 4 * 1024 * 1024;

enum BoundedLine {
    Eof,
    TooLong,
    Line(String),
}

/// One newline-terminated line of at most MAX_INTENT_BYTES. A longer line is
/// read to its end (so the stream stays in step) without being kept in memory.
async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
) -> std::io::Result<BoundedLine> {
    let mut buf = Vec::new();
    let (mut too_long, mut saw_bytes) = (false, false);
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            break;
        }
        saw_bytes = true;
        let newline = chunk.iter().position(|&b| b == b'\n');
        let used = newline.map_or(chunk.len(), |i| i + 1);
        if !too_long {
            let body = &chunk[..newline.unwrap_or(chunk.len())];
            if buf.len() + body.len() > MAX_INTENT_BYTES {
                too_long = true;
                buf = Vec::new();
            } else {
                buf.extend_from_slice(body);
            }
        }
        r.consume(used);
        if newline.is_some() {
            break;
        }
    }
    if !saw_bytes {
        return Ok(BoundedLine::Eof);
    }
    if too_long {
        return Ok(BoundedLine::TooLong);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(BoundedLine::Line(
        String::from_utf8_lossy(&buf).into_owned(),
    ))
}

async fn handle(stream: UnixStream, broker: Arc<Broker>, agent: String) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    loop {
        let line = match read_bounded_line(&mut reader).await? {
            BoundedLine::Eof => break,
            BoundedLine::Line(s) => s,
            BoundedLine::TooLong => {
                broker.malformed(&agent, "intent line too long");
                let v = Verdict {
                    id: "<oversized>".into(),
                    verdict: VerdictKind::Deny,
                    result: serde_json::Value::Null,
                    reason: format!("intent line too long (max {MAX_INTENT_BYTES} bytes)"),
                    token: None,
                };
                let mut out = serde_json::to_vec(&v)?;
                out.push(b'\n');
                write_half.write_all(&out).await?;
                write_half.flush().await?;
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let verdict = match serde_json::from_str::<Intent>(&line) {
            Ok(intent) => {
                eprintln!(
                    "{}",
                    crate::banner::dim(&format!(
                        "broker: intent id={} action={:?}",
                        intent.id, intent.action
                    ))
                );
                let v = broker.decide_as(&agent, &intent).await;
                eprintln!(
                    "broker:   -> {} ({})",
                    crate::banner::colorize_verdict(v.verdict),
                    v.reason
                );
                v
            }
            Err(e) => {
                broker.malformed(&agent, &format!("malformed intent: {e}"));
                Verdict {
                    id: "<unparseable>".into(),
                    verdict: VerdictKind::Deny,
                    result: serde_json::Value::Null,
                    reason: format!("malformed intent: {e}"),
                    token: None,
                }
            }
        };

        let mut out = serde_json::to_vec(&verdict)?;
        out.push(b'\n');
        write_half.write_all(&out).await?;
        write_half.flush().await?;
    }

    Ok(())
}

#[cfg(test)]
mod line_tests {
    use super::*;

    #[tokio::test]
    async fn an_oversized_line_is_refused_and_the_next_line_still_reads() {
        let mut data = vec![b'a'; MAX_INTENT_BYTES + 1];
        data.extend_from_slice(b"\nok\n");
        let mut r = BufReader::new(&data[..]);
        assert!(matches!(
            read_bounded_line(&mut r).await.unwrap(),
            BoundedLine::TooLong
        ));
        assert!(
            matches!(read_bounded_line(&mut r).await.unwrap(), BoundedLine::Line(s) if s == "ok")
        );
        assert!(matches!(
            read_bounded_line(&mut r).await.unwrap(),
            BoundedLine::Eof
        ));
    }

    #[tokio::test]
    async fn a_line_at_the_limit_is_read() {
        let mut data = vec![b'a'; MAX_INTENT_BYTES];
        data.push(b'\n');
        let mut r = BufReader::new(&data[..]);
        assert!(
            matches!(read_bounded_line(&mut r).await.unwrap(), BoundedLine::Line(s) if s.len() == MAX_INTENT_BYTES)
        );
    }
}
