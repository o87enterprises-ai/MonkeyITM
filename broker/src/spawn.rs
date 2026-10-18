//! Starting child agents and stopping them.
//!
//! Each child gets its own socket in a private directory; the broker serves that
//! socket as the child's id, so a child is known by where it connects, never by
//! what it says. The child itself is started by a launcher program (normally
//! `scripts/run-child.sh`, which runs it in bubblewrap) in its own process
//! group, so stopping it kills everything the launcher started.

use crate::{Broker, handle};
use eventlog::ROOT_AGENT;
use intent::Intent;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::future::Future;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex, Weak};

pub const MAX_TASK_BYTES: usize = 16 * 1024;
pub const DEFAULT_STEPS: u64 = 8;
pub const MAX_STEPS: u64 = 50;

pub struct SpawnConfig {
    /// Program and leading arguments. The broker appends the child's socket
    /// path, its agent id, its step limit and its task.
    pub launcher: Vec<String>,
    /// Directory for child sockets and output. Created with mode 0700; it must
    /// not exist yet, so nobody can have prepared it.
    pub dir: PathBuf,
    /// Group size, the root included.
    pub max_agents: usize,
}

struct Running {
    pgid: u32,
    killed: bool,
}

pub(crate) struct Spawner {
    cfg: SpawnConfig,
    broker: Weak<Broker>,
    running: Mutex<HashMap<String, Running>>,
}

impl Spawner {
    pub(crate) fn new(cfg: SpawnConfig, broker: Weak<Broker>) -> std::io::Result<Self> {
        if cfg.launcher.is_empty() {
            return Err(std::io::Error::other("spawning needs a launcher program"));
        }
        std::fs::DirBuilder::new().mode(0o700).create(&cfg.dir)?;
        Ok(Self {
            cfg,
            broker,
            running: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn running(&self) -> Vec<(String, u32)> {
        let mut v: Vec<_> = self
            .running
            .lock()
            .expect("spawn mutex poisoned")
            .iter()
            .map(|(id, r)| (id.clone(), r.pgid))
            .collect();
        v.sort();
        v
    }

    /// Kill every running child's process group. Returns how many were killed.
    /// This is deliberately every child, not only the newest: it is used for
    /// the tripwire, for shutdown, and when the halt fires while a child is
    /// still starting (`spawn_inner`), where stopping the whole group is the
    /// safe answer even though only one child was new.
    pub(crate) fn kill_all(&self) -> usize {
        let mut running = self.running.lock().expect("spawn mutex poisoned");
        for r in running.values_mut() {
            r.killed = true;
            kill_group(r.pgid);
        }
        running.len()
    }

    /// Boxed with an explicit `Send`: a child's connections run back through
    /// `decide_as`, which calls this, and the compiler cannot infer `Send`
    /// through that cycle on its own.
    pub(crate) fn spawn<'a>(
        &'a self,
        parent: &'a str,
        intent: &'a Intent,
    ) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>> {
        Box::pin(self.spawn_inner(parent, intent))
    }

    async fn spawn_inner(&self, parent: &str, intent: &Intent) -> Result<Value, String> {
        if parent != ROOT_AGENT {
            return Err("only the root agent may start agents".into());
        }
        let task = intent
            .params
            .get("task")
            .and_then(Value::as_str)
            .filter(|t| !t.trim().is_empty())
            .ok_or("spawn_agent needs a non-empty string `task`")?;
        if task.len() > MAX_TASK_BYTES {
            return Err(format!(
                "task is {} bytes; the limit is {MAX_TASK_BYTES}",
                task.len()
            ));
        }
        let steps = match intent.params.get("max_steps") {
            None => DEFAULT_STEPS,
            Some(v) => v
                .as_u64()
                .filter(|n| (1..=MAX_STEPS).contains(n))
                .ok_or(format!(
                    "max_steps must be a whole number from 1 to {MAX_STEPS}"
                ))?,
        };
        let broker = self.broker.upgrade().ok_or("broker is shutting down")?;

        let id = {
            let mut group = broker.group.lock().expect("group mutex poisoned");
            if group.len() >= self.cfg.max_agents {
                return Err(format!(
                    "the group already has {} agents; the limit is {}",
                    group.len(),
                    self.cfg.max_agents
                ));
            }
            let id = format!("a{}", group.len() + 1);
            group.add(&id, parent)?;
            id
        };
        let exited = |broker: &Broker, id: &str| {
            broker
                .group
                .lock()
                .expect("group mutex poisoned")
                .set_exited(id)
        };

        let sock = self.cfg.dir.join(format!("{id}.sock"));
        // The agent directory is already 0700; bind_private also makes the
        // socket itself 0600 so it never depends on the umask.
        let listener = match crate::bind_private(&sock) {
            Ok(l) => l,
            Err(e) => {
                broker.group.lock().expect("group mutex poisoned").forget(&id);
                return Err(format!("could not open a socket for {id}: {e}"));
            }
        };
        let serve = {
            let (broker, id) = (Arc::clone(&broker), id.clone());
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (b, id) = (Arc::clone(&broker), id.clone());
                    tokio::spawn(async move {
                        if let Err(e) = handle(stream, b, id.clone()).await {
                            eprintln!("broker: {id}: connection error: {e}");
                        }
                    });
                }
            })
        };

        let out = std::fs::File::create(self.cfg.dir.join(format!("{id}.out")))
            .and_then(|f| Ok((f.try_clone()?, f)));
        let child = out.and_then(|(stdout, stderr)| {
            let mut cmd = tokio::process::Command::new(&self.cfg.launcher[0]);
            cmd.args(&self.cfg.launcher[1..])
                .arg(&sock)
                .arg(&id)
                .arg(steps.to_string())
                .arg(task)
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .process_group(0);
            // If the broker dies without cleaning up (kill -9, a crash), the
            // kernel kills the launcher, and the sandbox it runs (bubblewrap's
            // --die-with-parent) goes with it. Without this a helper outlives
            // the broker that was supposed to hold it. (Linux; best effort:
            // the signal follows the thread that started the child.)
            #[cfg(target_os = "linux")]
            // SAFETY: only async-signal-safe prctl between fork and exec.
            unsafe {
                cmd.pre_exec(|| {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
                    Ok(())
                });
            }
            cmd.spawn()
        });
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                serve.abort();
                let _ = std::fs::remove_file(&sock);
                broker.group.lock().expect("group mutex poisoned").forget(&id);
                return Err(format!("could not start {id}: {e}"));
            }
        };
        let pgid = match child.id() {
            Some(p) => p,
            None => {
                // Just spawned; the id cannot already be gone. Do not
                // register a child whose process group we cannot kill.
                serve.abort();
                let _ = std::fs::remove_file(&sock);
                let _ = child.kill().await;
                exited(&broker, &id);
                return Err(format!(
                    "started {id} but its process id was already gone; \
                     the child is not registered and stop_children cannot reach it"
                ));
            }
        };
        self.running.lock().expect("spawn mutex poisoned").insert(
            id.clone(),
            Running {
                pgid,
                killed: false,
            },
        );
        broker.run_event(
            "agent_spawned",
            &json!({ "agent": id, "parent": parent, "task": task, "max_steps": steps }).to_string(),
        );

        {
            let (weak, id, sock) = (self.broker.clone(), id.clone(), sock.clone());
            tokio::spawn(async move {
                let status = child.wait().await;
                serve.abort();
                let _ = std::fs::remove_file(&sock);
                let Some(broker) = weak.upgrade() else { return };
                let killed = broker
                    .spawner
                    .get()
                    .and_then(|s| s.running.lock().ok()?.remove(&id))
                    .is_some_and(|r| r.killed);
                exited(&broker, &id);
                let reason = match (killed, status) {
                    (true, _) => "killed by the broker".to_string(),
                    (false, Ok(s)) => format!("exited ({s})"),
                    (false, Err(e)) => format!("lost track of the process: {e}"),
                };
                broker.run_event(
                    "agent_exited",
                    &json!({ "agent": id, "reason": reason }).to_string(),
                );
            });
        }

        // The halt may have fired while the child was starting.
        if broker.is_halted() {
            self.kill_all();
            return Err(crate::HALTED_REASON.to_string());
        }
        Ok(json!({ "agent": id }))
    }
}

fn kill_group(pgid: u32) {
    if pgid == 0 {
        return;
    }
    let _ = std::process::Command::new("kill")
        .args(["-KILL", "--", &format!("-{pgid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
