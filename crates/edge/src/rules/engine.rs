//! Rhai-backed rule evaluator.
//!
//! Each rule's `definition` JSON should contain a top-level `script`
//! string. The script runs with `event` bound in scope as a map of
//! the firing event's fields:
//!
//! ```rhai
//! // Available: event.id, event.kind, event.ts, event.device_id,
//! //            event.payload (the raw camera/device payload).
//! event.kind == "motion" && event.payload.zone == "front-door"
//! ```
//!
//! The script's return value drives the [`Outcome`]:
//!
//! * **bool / int / string / array / map (truthy)** — `matched = true`,
//!   no actions queued.
//! * **map with an `actions` array** — `matched = true` (or whatever
//!   the map's `matched` field says), actions are deserialised into
//!   [`ActionRequest`] descriptors and queued for the action layer.
//!
//! ```rhai
//! if event.kind == "motion" {
//!     return #{
//!         actions: [
//!             #{
//!                 kind: "http",
//!                 target: "https://hooks.example.com/notify",
//!                 method: "POST",
//!                 body: #{ alert: "motion detected" },
//!             }
//!         ]
//!     };
//! }
//! return false;
//! ```

use std::sync::Arc;

use anyhow::Context as _;
use rhai::{Dynamic, Engine, Map, Scope, AST};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::actions::ActionRequest;

#[derive(Debug, Clone)]
pub struct Script {
    ast: AST,
    /// Surrogate id of the rule whose script this is — for log lines.
    pub rule_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Outcome {
    pub matched: bool,
    #[serde(default)]
    pub actions: Vec<ActionRequest>,
}

/// Cloneable handle around a sandboxed Rhai engine. The inner `Engine`
/// is shared via `Arc` because Rhai's `Engine` is not itself `Clone` but
/// is `Send + Sync` so sharing across handlers is safe.
#[derive(Clone)]
pub struct RuleEngine {
    rhai: Arc<Engine>,
}

impl RuleEngine {
    pub fn new() -> Self {
        let mut rhai = Engine::new();
        // Sandboxing — bound the worst case of a buggy or hostile script.
        // 100k ops covers reasonable rules; trivial loops hit it fast.
        rhai.set_max_operations(100_000);
        rhai.set_max_call_levels(20);
        rhai.set_max_string_size(64 * 1024);
        rhai.set_max_array_size(10_000);
        rhai.set_max_map_size(1_000);
        Self {
            rhai: Arc::new(rhai),
        }
    }

    pub fn compile(&self, rule_id: i64, script: &str) -> anyhow::Result<Script> {
        let ast = self
            .rhai
            .compile(script)
            .with_context(|| format!("compiling rule {rule_id}"))?;
        Ok(Script { ast, rule_id })
    }

    pub fn evaluate(&self, script: &Script, event: &EventForRule) -> anyhow::Result<Outcome> {
        let event_map: Map = rhai::serde::to_dynamic(event)
            .context("event → rhai")?
            .try_cast::<Map>()
            .ok_or_else(|| anyhow::anyhow!("event must serialise to a map"))?;
        let mut scope = Scope::new();
        scope.push_constant("event", event_map);
        let result = self
            .rhai
            .eval_ast_with_scope::<Dynamic>(&mut scope, &script.ast)
            .with_context(|| format!("evaluating rule {}", script.rule_id))?;
        parse_outcome(result, script.rule_id)
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Subset of the event row passed into the script. Kept narrow so we
/// can add fields without invalidating cached scripts.
#[derive(Debug, Clone, Serialize)]
pub struct EventForRule {
    pub id: i64,
    pub kind: String,
    pub ts: i64,
    pub device_id: Option<i64>,
    pub payload: Value,
}

fn parse_outcome(v: Dynamic, rule_id: i64) -> anyhow::Result<Outcome> {
    if let Ok(b) = v.as_bool() {
        return Ok(Outcome {
            matched: b,
            actions: vec![],
        });
    }
    if let Ok(i) = v.as_int() {
        return Ok(Outcome {
            matched: i != 0,
            actions: vec![],
        });
    }
    if let Some(s) = v.clone().try_cast::<String>() {
        return Ok(Outcome {
            matched: !s.is_empty(),
            actions: vec![],
        });
    }
    if let Some(arr) = v.clone().try_cast::<rhai::Array>() {
        return Ok(Outcome {
            matched: !arr.is_empty(),
            actions: vec![],
        });
    }
    if let Some(map) = v.clone().try_cast::<Map>() {
        // Default match decision: a returned map is truthy when non-empty
        // unless the script explicitly sets `matched`.
        let matched = match map.get("matched") {
            Some(d) => d.as_bool().unwrap_or(true),
            None => !map.is_empty(),
        };
        let actions = match map.get("actions") {
            Some(d) => parse_actions(d.clone(), rule_id)?,
            None => vec![],
        };
        return Ok(Outcome { matched, actions });
    }
    Ok(Outcome::default())
}

fn parse_actions(d: Dynamic, rule_id: i64) -> anyhow::Result<Vec<ActionRequest>> {
    let arr = d.try_cast::<rhai::Array>().ok_or_else(|| {
        anyhow::anyhow!("rule {rule_id}: `actions` must be an array of action descriptors")
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for (idx, elt) in arr.into_iter().enumerate() {
        let action: ActionRequest = rhai::serde::from_dynamic(&elt)
            .with_context(|| format!("rule {rule_id}: parsing action at index {idx}"))?;
        out.push(action);
    }
    Ok(out)
}
