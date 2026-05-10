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
//! The script's return value is interpreted as the rule's match
//! decision: a truthy `bool` (or non-empty/non-zero map / array)
//! counts as a match. Phase 1 ignores any returned action descriptor;
//! the action layer lands in a follow-up PR.

use std::sync::Arc;

use anyhow::Context as _;
use rhai::{Engine, Map, Scope, AST};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Script {
    ast: AST,
    /// Surrogate id of the rule whose script this is — for log lines.
    pub rule_id: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub matched: bool,
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
            .eval_ast_with_scope::<rhai::Dynamic>(&mut scope, &script.ast)
            .with_context(|| format!("evaluating rule {}", script.rule_id))?;
        Ok(Outcome {
            matched: dynamic_to_bool(&result),
        })
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

fn dynamic_to_bool(v: &rhai::Dynamic) -> bool {
    if let Ok(b) = v.as_bool() {
        return b;
    }
    if let Ok(i) = v.as_int() {
        return i != 0;
    }
    if let Some(s) = v.clone().try_cast::<String>() {
        return !s.is_empty();
    }
    if let Some(arr) = v.clone().try_cast::<rhai::Array>() {
        return !arr.is_empty();
    }
    if let Some(map) = v.clone().try_cast::<rhai::Map>() {
        return !map.is_empty();
    }
    false
}
