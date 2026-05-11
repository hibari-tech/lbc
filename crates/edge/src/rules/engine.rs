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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;

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

struct CacheEntry {
    version: i64,
    script: Script,
    /// Server-clock unix-ms of the last time this rule fired. `None` =
    /// hasn't fired since process start. Persistence across restarts is
    /// out of scope; throttle effectively resets on reboot.
    last_fired_at: Option<i64>,
    /// Server-clock unix-ms of the last *script-matching* event. Distinct
    /// from `last_fired_at` because a debounced match still updates this
    /// (so the burst-end check keeps sliding) but does not produce a fire.
    last_match_at: Option<i64>,
}

/// Cloneable handle around a sandboxed Rhai engine plus a shared,
/// versioned cache of compiled rule scripts.
///
/// The inner `Engine` is shared via `Arc` because Rhai's `Engine` is
/// not itself `Clone` but is `Send + Sync` so sharing across handlers
/// is safe. The cache is keyed by `rule_id`; the entry's `version`
/// must match the row's current version or we recompile.
#[derive(Clone)]
pub struct RuleEngine {
    rhai: Arc<Engine>,
    cache: Arc<RwLock<HashMap<i64, CacheEntry>>>,
    compiles: Arc<AtomicU64>,
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
            cache: Arc::new(RwLock::new(HashMap::new())),
            compiles: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Total compiles since this engine was created. Useful for
    /// asserting the AST cache is doing its job.
    pub fn compiles_observed(&self) -> u64 {
        self.compiles.load(Ordering::Relaxed)
    }

    pub fn compile(&self, rule_id: i64, script: &str) -> anyhow::Result<Script> {
        let ast = self
            .rhai
            .compile(script)
            .with_context(|| format!("compiling rule {rule_id}"))?;
        self.compiles.fetch_add(1, Ordering::Relaxed);
        Ok(Script { ast, rule_id })
    }

    /// Compile-or-fetch: returns the cached `Script` if `version` still
    /// matches; otherwise compiles afresh and replaces the entry. The
    /// cache is the only durable state in `RuleEngine`.
    pub fn compile_or_fetch(
        &self,
        rule_id: i64,
        version: i64,
        src: &str,
    ) -> anyhow::Result<Script> {
        if let Ok(guard) = self.cache.read() {
            if let Some(entry) = guard.get(&rule_id) {
                if entry.version == version {
                    return Ok(entry.script.clone());
                }
            }
        }
        let script = self.compile(rule_id, src)?;
        if let Ok(mut guard) = self.cache.write() {
            guard.insert(
                rule_id,
                CacheEntry {
                    version,
                    script: script.clone(),
                    last_fired_at: None,
                    last_match_at: None,
                },
            );
        }
        Ok(script)
    }

    /// Returns the most recent fire time recorded via [`record_fire`],
    /// or `None` if the rule hasn't fired since this process started.
    pub fn last_fired_at(&self, rule_id: i64) -> Option<i64> {
        self.cache.read().ok()?.get(&rule_id)?.last_fired_at
    }

    /// Mark `rule_id` as having fired at `now_ms`. Lazy-creates a
    /// throttle slot if the rule isn't in the cache yet (shouldn't
    /// happen in normal flow but keeps the call infallible).
    pub fn record_fire(&self, rule_id: i64, now_ms: i64) {
        if let Ok(mut guard) = self.cache.write() {
            if let Some(entry) = guard.get_mut(&rule_id) {
                entry.last_fired_at = Some(now_ms);
            }
        }
    }

    /// Returns the most recent script-match time for `rule_id`. Used by
    /// the debounce primitive — "fire only on the first match of a burst,
    /// suppress until N seconds of quiet from any further match".
    pub fn last_match_at(&self, rule_id: i64) -> Option<i64> {
        self.cache.read().ok()?.get(&rule_id)?.last_match_at
    }

    /// Record a match — fired or debounce-suppressed — at `now_ms`. The
    /// debounce window slides on *every* match (so a sustained burst
    /// keeps suppressing) regardless of whether the dispatcher fired
    /// the rule.
    pub fn record_match(&self, rule_id: i64, now_ms: i64) {
        if let Ok(mut guard) = self.cache.write() {
            if let Some(entry) = guard.get_mut(&rule_id) {
                entry.last_match_at = Some(now_ms);
            }
        }
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
