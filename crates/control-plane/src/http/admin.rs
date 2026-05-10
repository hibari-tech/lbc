//! Minimal server-rendered admin web for the Control Plane.
//!
//! Phase 0 scope: read views over `account` / `branch` / `issued_license`
//! plus a form to mint a new account + first license_key. Bound to
//! whatever address `LBC_CP_SERVER__BIND` points at — typically
//! `127.0.0.1`. **No authentication** in Phase 0; do not expose this
//! beyond a trusted admin host without putting an auth proxy in front.
//! See `TOFIX.md` — admin-auth before deploy.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sqlx::Row;

use super::error::ApiError;
use super::AppState;

pub async fn index() -> Html<String> {
    Html(render(
        "LBC Control Plane — Admin",
        r#"<h1>LBC Control Plane</h1>
<p>Minimal admin surface (Phase 0).</p>
<ul>
  <li><a href="/admin/accounts">Accounts</a></li>
  <li><a href="/admin/branches">Branches</a></li>
  <li><a href="/admin/licenses">Issued licenses</a></li>
  <li><a href="/admin/accounts/new">Mint a new account + license key</a></li>
</ul>"#,
    ))
}

pub async fn list_accounts(State(state): State<AppState>) -> Result<Html<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT a.id, a.name, a.tier, a.created_at, \
                (SELECT COUNT(*) FROM license_key k WHERE k.account_id = a.id) AS keys, \
                (SELECT COUNT(*) FROM branch b WHERE b.account_id = a.id) AS branches \
         FROM account a ORDER BY a.id ASC",
    )
    .fetch_all(state.db.pool())
    .await?;
    let mut body = String::from("<h1>Accounts</h1><table>");
    body.push_str(
        "<tr><th>id</th><th>name</th><th>tier</th><th>keys</th><th>branches</th><th>created</th></tr>",
    );
    for r in rows {
        let id: i64 = r.get("id");
        let name: String = r.get("name");
        let tier: String = r.get("tier");
        let keys: i64 = r.get("keys");
        let branches: i64 = r.get("branches");
        let created_at: i64 = r.get("created_at");
        body.push_str(&format!(
            "<tr><td>{id}</td><td>{}</td><td>{}</td><td>{keys}</td><td>{branches}</td><td>{created_at}</td></tr>",
            esc(&name),
            esc(&tier),
        ));
    }
    body.push_str("</table>");
    body.push_str(r#"<p><a href="/admin/accounts/new">Mint new account</a></p>"#);
    Ok(Html(render("Accounts", &body)))
}

pub async fn list_branches(State(state): State<AppState>) -> Result<Html<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT b.id, b.account_id, b.name, b.hardware_fingerprint, b.created_at \
         FROM branch b ORDER BY b.id ASC",
    )
    .fetch_all(state.db.pool())
    .await?;
    let mut body = String::from("<h1>Branches</h1><table>");
    body.push_str(
        "<tr><th>id</th><th>account</th><th>name</th><th>fingerprint</th><th>created</th></tr>",
    );
    for r in rows {
        let id: i64 = r.get("id");
        let account_id: i64 = r.get("account_id");
        let name: String = r.get("name");
        let fp: String = r.get("hardware_fingerprint");
        let created_at: i64 = r.get("created_at");
        body.push_str(&format!(
            "<tr><td>{id}</td><td>{account_id}</td><td>{}</td><td><code>{}</code></td><td>{created_at}</td></tr>",
            esc(&name),
            esc(&fp),
        ));
    }
    body.push_str("</table>");
    Ok(Html(render("Branches", &body)))
}

pub async fn list_licenses(State(state): State<AppState>) -> Result<Html<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, license_key_id, branch_id, issued_at, expires_at, last_seen, revoked_at \
         FROM issued_license ORDER BY id DESC",
    )
    .fetch_all(state.db.pool())
    .await?;
    let mut body = String::from("<h1>Issued licenses</h1><table>");
    body.push_str(
        "<tr><th>id</th><th>key</th><th>branch</th><th>issued</th><th>expires</th>\
         <th>last_seen</th><th>revoked_at</th><th></th></tr>",
    );
    for r in rows {
        let id: i64 = r.get("id");
        let key_id: i64 = r.get("license_key_id");
        let branch_id: i64 = r.get("branch_id");
        let issued_at: i64 = r.get("issued_at");
        let expires_at: i64 = r.get("expires_at");
        let last_seen: Option<i64> = r.get("last_seen");
        let revoked_at: Option<i64> = r.get("revoked_at");
        let revoke_btn = if revoked_at.is_some() {
            "revoked".to_string()
        } else {
            format!(
                r#"<form method="POST" action="/admin/licenses/{id}/revoke" style="display:inline">\
                   <button type="submit">revoke</button></form>"#
            )
        };
        body.push_str(&format!(
            "<tr><td>{id}</td><td>{key_id}</td><td>{branch_id}</td><td>{issued_at}</td>\
             <td>{expires_at}</td><td>{}</td><td>{}</td><td>{revoke_btn}</td></tr>",
            last_seen.map_or_else(|| "-".to_string(), |v| v.to_string()),
            revoked_at.map_or_else(|| "-".to_string(), |v| v.to_string()),
        ));
    }
    body.push_str("</table>");
    Ok(Html(render("Issued licenses", &body)))
}

pub async fn new_account_form() -> Html<String> {
    Html(render(
        "Mint account",
        r#"<h1>Mint account + license key</h1>
<form method="POST" action="/admin/accounts">
  <p><label>Account name <input name="name" required></label></p>
  <p><label>Email <input name="email" type="email" required></label></p>
  <p><label>Tier
    <select name="tier">
      <option value="starter">starter</option>
      <option value="pro" selected>pro</option>
      <option value="enterprise">enterprise</option>
    </select></label></p>
  <p><label>Branches allowed <input name="branches" type="number" value="1" min="1"></label></p>
  <button type="submit">Create</button>
</form>"#,
    ))
}

#[derive(Debug, Deserialize)]
pub struct NewAccountForm {
    pub name: String,
    pub email: String,
    pub tier: String,
    pub branches: i64,
}

pub async fn create_account(
    State(state): State<AppState>,
    Form(req): Form<NewAccountForm>,
) -> Result<Html<String>, ApiError> {
    let now_ms = now_secs() * 1000;
    let account_id: i64 = sqlx::query_scalar(
        "INSERT INTO account (name, email, tier, created_at) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(&req.name)
    .bind(&req.email)
    .bind(&req.tier)
    .bind(now_ms)
    .fetch_one(state.db.pool())
    .await?;
    let key = generate_key();
    let key_hash = blake3::hash(key.as_bytes());
    sqlx::query(
        "INSERT INTO license_key (account_id, key_hash, tier, allowed_branch_count, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(key_hash.as_bytes().as_slice())
    .bind(&req.tier)
    .bind(req.branches.max(1))
    .bind(0_i64)
    .bind(now_ms)
    .execute(state.db.pool())
    .await?;
    let body = format!(
        r#"<h1>Account #{account_id} created</h1>
<p>Save this license key — it is shown only once:</p>
<pre><code>{}</code></pre>
<p><a href="/admin/accounts">Back to accounts</a></p>"#,
        esc(&key),
    );
    Ok(Html(render("Account created", &body)))
}

pub async fn revoke_form(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let now_ms = now_secs() * 1000;
    let result =
        sqlx::query("UPDATE issued_license SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?")
            .bind(now_ms)
            .bind(id)
            .execute(state.db.pool())
            .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok((StatusCode::SEE_OTHER, Redirect::to("/admin/licenses")).into_response())
}

fn render(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>{}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;}}
table{{border-collapse:collapse;width:100%;}}
th,td{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem;}}
th{{background:#f4f4f4;}}
code{{font-size:.85rem;word-break:break-all;}}
</style></head><body>{body}</body></html>"#,
        esc(title)
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn generate_key() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(48);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("LBC-{}", hex.to_uppercase())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
