//! Rule engine — compiles and evaluates user rules against events.
//!
//! Phase 1 first slice: Rhai-scripted rules only. The visual builder
//! lands on top of this once §0.7 / SPIKE-01 picks a frontend stack.
//!
//! Sandboxing: Rhai has no file or network access by default. We bound
//! the cost of any single evaluation with `Engine::set_max_operations`
//! and friends so a runaway loop can't stall the runtime.

pub mod dispatch;
pub mod engine;
pub mod scheduler;

pub use dispatch::evaluate_event;
pub use engine::{Outcome, RuleEngine, Script};
pub use scheduler::{evaluate_scheduled, parse_schedule, ScheduledReport};
