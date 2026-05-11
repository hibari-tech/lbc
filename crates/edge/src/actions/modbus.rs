//! Modbus/TCP action via `tokio-modbus`.
//!
//! Industrial gear (PLCs, relay boards, building-management controllers)
//! speaks Modbus on a LAN. Rule scripts use it to flip a coil or load a
//! holding register when an event matches.
//!
//! ```rhai
//! return #{
//!     actions: [
//!         // Energise relay 5 on the alarm board.
//!         #{
//!             kind: "modbus",
//!             target: "10.0.5.40:502",
//!             function: "write_coil",
//!             unit_id: 1,
//!             address: 5,
//!             body: true,
//!         },
//!         // Set holding register 100 to value 1234.
//!         #{
//!             kind: "modbus",
//!             target: "10.0.5.40:502",
//!             function: "write_register",
//!             unit_id: 1,
//!             address: 100,
//!             body: 1234,
//!         },
//!     ]
//! };
//! ```
//!
//! ## Scope (Phase 1)
//!
//! * Modbus/TCP only. Modbus/RTU (serial) is a follow-up.
//! * Writes only — `write_single_coil` (FC 0x05) and
//!   `write_single_register` (FC 0x06). Reads (FC 0x01..0x04) are useful
//!   for ingest rather than actions and land separately.
//! * Per-action connect / write / disconnect. Industrial sessions are
//!   intrinsically cheap; pooling can come if profiling demands it.
//!
//! ## Network policy
//!
//! Modbus has no transport-level auth and is explicitly an industrial
//! LAN protocol — the SSRF guard that gates outbound HTTP does **not**
//! apply here. If a rule script directs a Modbus write at a public
//! address it'll just time out; the worst case (LAN device, no auth)
//! is the entire intended use. Treat rule scripts as trusted admin
//! content.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio_modbus::client::{tcp, Client, Writer};
use tokio_modbus::slave::Slave;

use super::{ActionRequest, ActionResult};

/// Bounded per-action timeout so a non-responsive PLC doesn't hold up
/// the dispatcher.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModbusOp {
    WriteCoil(bool),
    WriteRegister(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModbusPlan {
    pub addr: SocketAddr,
    pub unit_id: u8,
    pub address: u16,
    pub op: ModbusOp,
}

pub async fn execute(action: &ActionRequest) -> ActionResult {
    let start = Instant::now();

    let plan = match plan_request(action) {
        Ok(p) => p,
        Err(e) => return error(&e, start),
    };

    let connect = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tcp::connect_slave(plan.addr, Slave(plan.unit_id)),
    )
    .await;
    let mut ctx = match connect {
        Ok(Ok(ctx)) => ctx,
        Ok(Err(e)) => return error(&format!("connect to {}: {e}", plan.addr), start),
        Err(_) => return error(&format!("connect to {} timed out", plan.addr), start),
    };

    let write = tokio::time::timeout(WRITE_TIMEOUT, async {
        match plan.op {
            ModbusOp::WriteCoil(v) => ctx.write_single_coil(plan.address, v).await,
            ModbusOp::WriteRegister(v) => ctx.write_single_register(plan.address, v).await,
        }
    })
    .await;

    let result = match write {
        Ok(Ok(Ok(()))) => ActionResult {
            ok: true,
            status: 0,
            response: format!(
                "{} addr={} unit={} ok",
                op_label(&plan.op),
                plan.address,
                plan.unit_id
            ),
            latency_ms: elapsed_ms(start),
        },
        Ok(Ok(Err(exc))) => error(&format!("modbus exception: {exc:?}"), start),
        Ok(Err(e)) => error(&format!("modbus transport: {e}"), start),
        Err(_) => error("modbus write timed out", start),
    };

    let _ = ctx.disconnect().await;
    result
}

/// Validate an action descriptor and project it into a [`ModbusPlan`].
/// Pure — no IO — so every parse path is testable without a PLC.
pub fn plan_request(action: &ActionRequest) -> Result<ModbusPlan, String> {
    if action.target.is_empty() {
        return Err("Modbus action requires `target` (host:port)".into());
    }
    let addr = SocketAddr::from_str(&action.target).map_err(|e| {
        format!(
            "Modbus `target` must be a literal SocketAddr (host:port), got {:?}: {e}",
            action.target
        )
    })?;
    let unit_id = action.unit_id.unwrap_or(1);
    if unit_id > 247 {
        return Err(format!("Modbus `unit_id` must be 0..=247, got {unit_id}"));
    }
    let address = action
        .address
        .ok_or_else(|| "Modbus action requires `address` (0..=65535)".to_string())?;
    let function = action
        .function
        .as_deref()
        .ok_or_else(|| "Modbus action requires `function`".to_string())?;
    let op = match function {
        "write_coil" => ModbusOp::WriteCoil(parse_coil_value(action.body.as_ref())?),
        "write_register" => ModbusOp::WriteRegister(parse_register_value(action.body.as_ref())?),
        other => {
            return Err(format!(
                "unsupported Modbus function {other:?}; Phase 1 supports write_coil, write_register"
            ));
        }
    };
    Ok(ModbusPlan {
        addr,
        unit_id,
        address,
        op,
    })
}

fn parse_coil_value(body: Option<&Value>) -> Result<bool, String> {
    match body {
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(|i| i != 0)
            .ok_or_else(|| "Modbus write_coil body must be bool or integer".into()),
        Some(other) => Err(format!(
            "Modbus write_coil body must be bool, got {other:?}"
        )),
        None => Err("Modbus write_coil requires a body (bool)".into()),
    }
}

fn parse_register_value(body: Option<&Value>) -> Result<u16, String> {
    match body {
        Some(Value::Number(n)) => {
            let i = n.as_i64().ok_or_else(|| {
                "Modbus write_register body must be an integer 0..=65535".to_string()
            })?;
            u16::try_from(i)
                .map_err(|_| format!("Modbus write_register body {i} out of range (0..=65535)"))
        }
        Some(other) => Err(format!(
            "Modbus write_register body must be a 0..=65535 integer, got {other:?}"
        )),
        None => Err("Modbus write_register requires a body (0..=65535 integer)".into()),
    }
}

fn op_label(op: &ModbusOp) -> &'static str {
    match op {
        ModbusOp::WriteCoil(_) => "write_coil",
        ModbusOp::WriteRegister(_) => "write_register",
    }
}

fn error(msg: &str, start: Instant) -> ActionResult {
    ActionResult {
        ok: false,
        status: 0,
        response: msg.to_string(),
        latency_ms: elapsed_ms(start),
    }
}

fn elapsed_ms(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX)
}
