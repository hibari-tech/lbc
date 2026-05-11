//! MQTT publish action via `rumqttc`.
//!
//! Phase 1: per-action connect / publish / disconnect against a
//! globally-configured broker. TLS, authenticated brokers, and a
//! persistent shared client connection are follow-ups — for the
//! event volumes Phase 1 targets (a handful of fires per second per
//! branch), per-action connect overhead is acceptable.
//!
//! ```rhai
//! return #{
//!     actions: [
//!         #{
//!             kind: "mqtt",
//!             topic: "lbc/branch/1/alerts",
//!             qos: 1,
//!             body: #{ kind: "motion", zone: "front-door" },
//!         }
//!     ]
//! };
//! ```
//!
//! The eventloop is driven in a spawned task while the publish is
//! in flight; for QoS 0 the publish is acknowledged locally as soon
//! as it lands in the outgoing queue, and we give the loop a short
//! grace period to flush the bytes before disconnecting.

use std::time::{Duration, Instant};

use rumqttc::{AsyncClient, MqttOptions, QoS};

use super::{ActionRequest, ActionResult, MqttConfig};

/// How long to let the eventloop run after `publish` so the bytes
/// actually reach the wire before we disconnect.
const FLUSH_GRACE: Duration = Duration::from_millis(250);

pub async fn execute(action: &ActionRequest, cfg: &MqttConfig) -> ActionResult {
    let start = Instant::now();

    if cfg.server.is_empty() {
        return error(
            "MQTT not configured — set actions.mqtt.server (LBC_EDGE_ACTIONS__MQTT__SERVER)",
            start,
        );
    }

    let plan = match plan_publish(action) {
        Ok(p) => p,
        Err(e) => return error(&e, start),
    };

    let client_id = if cfg.client_id.is_empty() {
        format!("lbc-edge-{}", random_suffix())
    } else {
        cfg.client_id.clone()
    };
    let port = if cfg.port == 0 { 1883 } else { cfg.port };
    let mut opts = MqttOptions::new(client_id, &cfg.server, port);
    opts.set_keep_alive(Duration::from_secs(15));
    if !cfg.username.is_empty() {
        opts.set_credentials(&cfg.username, &cfg.password);
    }

    let (client, mut eventloop) = AsyncClient::new(opts, 10);
    let driver = tokio::spawn(async move {
        loop {
            if eventloop.poll().await.is_err() {
                break;
            }
        }
    });

    if let Err(e) = client
        .publish(&plan.topic, plan.qos, plan.retain, plan.payload.clone())
        .await
    {
        let _ = client.disconnect().await;
        driver.abort();
        return error(&format!("publish failed: {e}"), start);
    }

    tokio::time::sleep(FLUSH_GRACE).await;
    let _ = client.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_millis(500), driver).await;

    ActionResult {
        ok: true,
        status: 0,
        response: format!(
            "published {bytes} bytes to `{topic}` (qos {qos})",
            bytes = plan.payload.len(),
            topic = plan.topic,
            qos = qos_as_u8(plan.qos)
        ),
        latency_ms: elapsed_ms(start),
    }
}

#[derive(Debug, Clone)]
pub struct PublishPlan {
    pub topic: String,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Vec<u8>,
}

/// Validate the action and project it into a `PublishPlan`. Pure /
/// no-IO so the validation paths are testable without a broker.
pub fn plan_publish(action: &ActionRequest) -> Result<PublishPlan, String> {
    let topic = action
        .topic
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "MQTT action requires `topic`".to_string())?
        .to_string();
    let qos = parse_qos(action.qos.unwrap_or(0))?;
    let retain = action.retain.unwrap_or(false);
    let payload = serialise_body(action.body.as_ref());
    Ok(PublishPlan {
        topic,
        qos,
        retain,
        payload,
    })
}

fn parse_qos(n: u8) -> Result<QoS, String> {
    match n {
        0 => Ok(QoS::AtMostOnce),
        1 => Ok(QoS::AtLeastOnce),
        2 => Ok(QoS::ExactlyOnce),
        other => Err(format!("invalid MQTT QoS {other} (must be 0, 1, or 2)")),
    }
}

fn qos_as_u8(q: QoS) -> u8 {
    match q {
        QoS::AtMostOnce => 0,
        QoS::AtLeastOnce => 1,
        QoS::ExactlyOnce => 2,
    }
}

fn serialise_body(body: Option<&serde_json::Value>) -> Vec<u8> {
    match body {
        Some(serde_json::Value::String(s)) => s.as_bytes().to_vec(),
        Some(other) => other.to_string().into_bytes(),
        None => Vec::new(),
    }
}

fn random_suffix() -> String {
    use rand_core::RngCore;
    let mut buf = [0u8; 6];
    rand_core::OsRng.fill_bytes(&mut buf);
    let mut hex = String::with_capacity(12);
    for b in buf {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
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
