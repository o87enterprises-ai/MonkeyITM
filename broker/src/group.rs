//! The agents in one group and the messages between them. One broker hosts the
//! whole group; an agent's id comes from the socket it connects on, so every
//! check here trusts `from` and nothing inside the intent.

use eventlog::ROOT_AGENT;
use intent::{Action, Intent};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_QUEUED: usize = 100;
pub const MAX_PER_RECV: usize = 20;

struct Member {
    parent: Option<String>,
    alive: bool,
    inbox: VecDeque<(String, String)>,
}

pub struct Group {
    members: HashMap<String, Member>,
}

impl Default for Group {
    fn default() -> Self {
        let mut members = HashMap::new();
        members.insert(
            ROOT_AGENT.to_string(),
            Member {
                parent: None,
                alive: true,
                inbox: VecDeque::new(),
            },
        );
        Self { members }
    }
}

/// Actions the broker carries out itself rather than handing to the executor.
pub fn is_routed(a: Action) -> bool {
    matches!(a, Action::SendMessage | Action::RecvMessage)
}

impl Group {
    pub fn add(&mut self, id: &str, parent: &str) -> Result<(), String> {
        if self.members.contains_key(id) {
            return Err(format!("agent {id} already exists"));
        }
        match self.members.get(parent) {
            Some(p) if p.alive => {}
            _ => return Err(format!("parent {parent} is not a running agent")),
        }
        self.members.insert(
            id.to_string(),
            Member {
                parent: Some(parent.to_string()),
                alive: true,
                inbox: VecDeque::new(),
            },
        );
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn parent_of(&self, id: &str) -> Option<&str> {
        self.members.get(id).and_then(|m| m.parent.as_deref())
    }

    /// Drop an agent that never started (its socket or process could not be set up), so
    /// the failed attempt does not use up one of the group's places. Only for an agent
    /// that has acted nowhere: the log never mentions it.
    pub fn forget(&mut self, id: &str) {
        self.members.remove(id);
    }

    /// An exited agent keeps its id (the log refers to it) but receives nothing more.
    pub fn set_exited(&mut self, id: &str) {
        if let Some(m) = self.members.get_mut(id) {
            m.alive = false;
            m.inbox.clear();
        }
    }

    pub fn route(&mut self, from: &str, intent: &Intent) -> Result<Value, String> {
        match intent.action {
            Action::SendMessage => self.send(from, &intent.params),
            Action::RecvMessage => self.recv(from),
            _ => Err("not a message action".into()),
        }
    }

    fn send(&mut self, from: &str, params: &Value) -> Result<Value, String> {
        let to = params
            .get("to")
            .and_then(Value::as_str)
            .ok_or("send_message needs a string `to`")?;
        let body = params
            .get("body")
            .and_then(Value::as_str)
            .ok_or("send_message needs a string `body`")?;
        if body.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "message is {} bytes; the limit is {MAX_MESSAGE_BYTES}",
                body.len()
            ));
        }
        if to == from {
            return Err("an agent cannot message itself".into());
        }
        let sender_parent = self
            .members
            .get(from)
            .ok_or_else(|| format!("unknown sender {from}"))?
            .parent
            .clone();
        let target = self
            .members
            .get_mut(to)
            .ok_or_else(|| format!("no agent {to} in this group"))?;
        let related =
            target.parent.as_deref() == Some(from) || sender_parent.as_deref() == Some(to);
        if !related {
            return Err("agents may message only their parent or their own children".into());
        }
        if !target.alive {
            return Err(format!("{to} has exited"));
        }
        if target.inbox.len() >= MAX_QUEUED {
            return Err(format!(
                "{to} has {MAX_QUEUED} unread messages; nothing more is queued until it reads them"
            ));
        }
        target.inbox.push_back((from.to_string(), body.to_string()));
        Ok(json!({ "queued": true, "to": to }))
    }

    fn recv(&mut self, from: &str) -> Result<Value, String> {
        let me = self
            .members
            .get_mut(from)
            .ok_or_else(|| format!("unknown agent {from}"))?;
        if !me.alive {
            return Err(format!("{from} has exited"));
        }
        let n = me.inbox.len().min(MAX_PER_RECV);
        let messages: Vec<Value> = me
            .inbox
            .drain(..n)
            .map(|(f, b)| json!({ "from": f, "body": b }))
            .collect();
        Ok(json!({ "messages": messages, "remaining": me.inbox.len() }))
    }
}
