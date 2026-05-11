//! FTP upload action — fifth action kind.
//!
//! Rule scripts can stash an evidence payload (a JSON snapshot, a
//! short log excerpt, etc.) on an internal FTP target. The target is
//! a full URL so the destination filename travels in-band:
//!
//! ```rhai
//! return #{
//!     actions: [
//!         #{
//!             kind: "ftp",
//!             target: "ftp://uploader:secret@10.0.5.10:21/incoming/alert.json",
//!             body: #{ alert: "motion", zone: event.payload.zone },
//!         }
//!     ]
//! };
//! ```
//!
//! ## Scope (Phase 1)
//!
//! * Plain FTP (RFC 959) over TCP, passive mode only. FTPS / SFTP
//!   land later if a deployment needs them — the action shape stays
//!   the same.
//! * Uploads only (`STOR`). Listing / deletion isn't a rule-action
//!   concern.
//! * Credentials travel in the URL. Anonymous login is used when the
//!   URL has no userinfo (`ftp://host/path` → `USER anonymous` /
//!   `PASS anonymous@`).
//! * Per-action connect / login / store / quit. The expected volume
//!   (handful of fires per second per branch) doesn't warrant a
//!   pooled control connection.
//!
//! ## Network policy
//!
//! Like Modbus, FTP is treated as an internal-LAN protocol — the
//! SSRF guard that gates outbound HTTP does **not** apply. Rule
//! scripts are admin-authored and the typical FTP target is a NAS
//! sitting on the same wire as the edge node.

use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;
use url::Url;

use super::{ActionRequest, ActionResult};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpPlan {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub path: String,
    pub payload: Vec<u8>,
}

pub async fn execute(action: &ActionRequest) -> ActionResult {
    let start = Instant::now();
    let plan = match plan_request(action) {
        Ok(p) => p,
        Err(e) => return error(&e, start),
    };

    match upload(&plan).await {
        Ok(()) => ActionResult {
            ok: true,
            status: 0,
            response: format!(
                "stored {bytes} bytes at ftp://{host}:{port}{path}",
                bytes = plan.payload.len(),
                host = plan.host,
                port = plan.port,
                path = plan.path
            ),
            latency_ms: elapsed_ms(start),
        },
        Err(e) => error(&e, start),
    }
}

/// Validate an action descriptor and project it into a [`FtpPlan`].
/// Pure — no IO — so every parse path is testable without an FTP
/// server.
pub fn plan_request(action: &ActionRequest) -> Result<FtpPlan, String> {
    if action.target.is_empty() {
        return Err("FTP action requires `target` (ftp://... URL)".into());
    }
    let url =
        Url::parse(&action.target).map_err(|e| format!("FTP `target` must be a valid URL: {e}"))?;
    if url.scheme() != "ftp" {
        return Err(format!(
            "FTP `target` must use the ftp:// scheme, got {:?}",
            url.scheme()
        ));
    }
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "FTP `target` is missing host".to_string())?
        .to_string();
    let port = url.port().unwrap_or(21);
    // FTP credentials in the URL are taken verbatim — percent-encoding
    // in usernames / passwords is unusual enough in real deployments
    // that we skip decoding to avoid a transitive dep on
    // `percent-encoding`. A credential containing `%`, `/`, `@`, or
    // `:` should be configured out-of-band rather than in the URL.
    let username = if url.username().is_empty() {
        "anonymous".to_string()
    } else {
        url.username().to_string()
    };
    let password = match url.password() {
        Some(p) => p.to_string(),
        None if username == "anonymous" => "anonymous@".to_string(),
        None => String::new(),
    };
    let path = url.path().to_string();
    if path.is_empty() || path == "/" {
        return Err("FTP `target` must include a file path (e.g. /incoming/alert.json)".into());
    }
    let payload = serialise_body(action.body.as_ref())?;
    Ok(FtpPlan {
        host,
        port,
        username,
        password,
        path,
        payload,
    })
}

fn serialise_body(body: Option<&Value>) -> Result<Vec<u8>, String> {
    match body {
        Some(Value::String(s)) => Ok(s.as_bytes().to_vec()),
        Some(Value::Null) | None => Err("FTP action requires a non-empty `body`".into()),
        Some(other) => Ok(other.to_string().into_bytes()),
    }
}

async fn upload(plan: &FtpPlan) -> Result<(), String> {
    let addr = format!("{}:{}", plan.host, plan.port);
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("ftp connect to {addr} timed out"))?
        .map_err(|e| format!("ftp connect to {addr}: {e}"))?;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    // 220 banner
    read_reply(&mut reader, 220).await?;

    send_cmd(&mut write, &format!("USER {}\r\n", plan.username)).await?;
    let (code, _) = read_reply_any(&mut reader).await?;
    match code {
        230 => {}
        331 => {
            send_cmd(&mut write, &format!("PASS {}\r\n", plan.password)).await?;
            read_reply(&mut reader, 230).await?;
        }
        other => return Err(format!("ftp USER unexpected reply {other}")),
    }

    send_cmd(&mut write, "TYPE I\r\n").await?;
    read_reply(&mut reader, 200).await?;

    send_cmd(&mut write, "PASV\r\n").await?;
    let (_, pasv_line) = read_reply_exact(&mut reader, 227).await?;
    let data_addr = parse_pasv(&pasv_line)?;

    let data_stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&data_addr))
        .await
        .map_err(|_| format!("ftp data connect to {data_addr} timed out"))?
        .map_err(|e| format!("ftp data connect to {data_addr}: {e}"))?;

    send_cmd(&mut write, &format!("STOR {}\r\n", plan.path)).await?;
    let (code, _) = read_reply_any(&mut reader).await?;
    if code != 150 && code != 125 {
        return Err(format!("ftp STOR unexpected reply {code}"));
    }

    let (_, mut data_write) = data_stream.into_split();
    tokio::time::timeout(TRANSFER_TIMEOUT, data_write.write_all(&plan.payload))
        .await
        .map_err(|_| "ftp data write timed out".to_string())?
        .map_err(|e| format!("ftp data write: {e}"))?;
    data_write
        .shutdown()
        .await
        .map_err(|e| format!("ftp data shutdown: {e}"))?;

    read_reply(&mut reader, 226).await?;

    let _ = send_cmd(&mut write, "QUIT\r\n").await;
    Ok(())
}

async fn send_cmd(write: &mut tokio::net::tcp::OwnedWriteHalf, cmd: &str) -> Result<(), String> {
    tokio::time::timeout(COMMAND_TIMEOUT, write.write_all(cmd.as_bytes()))
        .await
        .map_err(|_| "ftp command write timed out".to_string())?
        .map_err(|e| format!("ftp write: {e}"))
}

async fn read_reply(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected: u16,
) -> Result<String, String> {
    let (code, line) = read_reply_any(reader).await?;
    if code == expected {
        Ok(line)
    } else {
        Err(format!("ftp expected reply {expected}, got {code}: {line}"))
    }
}

async fn read_reply_exact(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected: u16,
) -> Result<(u16, String), String> {
    let (code, line) = read_reply_any(reader).await?;
    if code == expected {
        Ok((code, line))
    } else {
        Err(format!("ftp expected reply {expected}, got {code}: {line}"))
    }
}

/// Read one FTP reply, joining multi-line continuations into a single
/// owned `String`. The numeric reply code is returned alongside.
async fn read_reply_any(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<(u16, String), String> {
    let first = read_line(reader).await?;
    let code = parse_code(&first)?;
    let mut combined = first.clone();
    // Multi-line reply: "<code>-" on the first line, "<code> " on the
    // terminator. Keep reading until we see the terminator.
    if first.len() >= 4 && first.as_bytes()[3] == b'-' {
        let prefix = format!("{code} ");
        loop {
            let next = read_line(reader).await?;
            combined.push_str(&next);
            if next.starts_with(&prefix) {
                break;
            }
        }
    }
    Ok((code, combined))
}

async fn read_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<String, String> {
    let mut buf = String::new();
    let n = tokio::time::timeout(COMMAND_TIMEOUT, reader.read_line(&mut buf))
        .await
        .map_err(|_| "ftp read timed out".to_string())?
        .map_err(|e| format!("ftp read: {e}"))?;
    if n == 0 {
        return Err("ftp connection closed unexpectedly".into());
    }
    Ok(buf)
}

fn parse_code(line: &str) -> Result<u16, String> {
    line.get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed FTP reply: {line:?}"))
}

/// Parse the `(h1,h2,h3,h4,p1,p2)` tuple out of a 227 PASV reply.
pub fn parse_pasv(line: &str) -> Result<String, String> {
    let open = line
        .find('(')
        .ok_or_else(|| format!("malformed PASV reply (no `(`): {line:?}"))?;
    let close = line[open..]
        .find(')')
        .map(|i| open + i)
        .ok_or_else(|| format!("malformed PASV reply (no `)`): {line:?}"))?;
    let inner = &line[open + 1..close];
    let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
    if parts.len() != 6 {
        return Err(format!(
            "PASV expects 6 comma-separated octets, got {inner:?}"
        ));
    }
    let mut nums = [0u16; 6];
    for (i, part) in parts.iter().enumerate() {
        nums[i] = part
            .parse::<u16>()
            .map_err(|e| format!("PASV component {part:?} not numeric: {e}"))?;
        if i < 4 && nums[i] > 255 {
            return Err(format!("PASV ip octet out of range: {}", nums[i]));
        }
        if i >= 4 && nums[i] > 255 {
            return Err(format!("PASV port byte out of range: {}", nums[i]));
        }
    }
    let ip = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
    let port = (nums[4] << 8) | nums[5];
    Ok(format!("{ip}:{port}"))
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
