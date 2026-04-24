//! Minimal landing page served at `GET /`.
//!
//! A self-contained HTML page that informs browser visitors what this server
//! is and how to connect a JMAP client to it.

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;

pub const HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>stoa JMAP mail server</title>
  <style>
    body { font-family: sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }
    code { background: #f4f4f4; padding: 0.1em 0.3em; border-radius: 3px; }
    a { color: #0066cc; }
  </style>
</head>
<body>
  <h1>stoa JMAP mail server</h1>
  <p>This server speaks the <a href="https://jmap.io/">JMAP protocol</a> (RFC&nbsp;8620 / RFC&nbsp;8621).
  Connect any RFC&nbsp;8620-compatible mail client to get started.</p>

  <h2>Client setup</h2>
  <p>Point your JMAP client at this server's base URL. Most clients support
  automatic discovery via <code>/.well-known/jmap</code>.</p>
  <ul>
    <li><strong>Discovery URL:</strong> <code>/.well-known/jmap</code></li>
    <li><strong>API URL:</strong> <code>/jmap/api</code></li>
  </ul>

  <h2>Recommended clients</h2>
  <ul>
    <li><a href="https://github.com/jmaprs/lollipop">Lollipop</a> — Vue.js JMAP web client</li>
    <li><a href="https://cypht.org/">Cypht</a> — modular open-source webmail</li>
  </ul>

  <h2>Operator note</h2>
  <p>Set <code>[listen] base_url</code> in your config to the externally-reachable
  server hostname (e.g. <code>https://mail.example.com</code>). This is required for
  blob downloads and client autodiscovery to work correctly from a remote browser.</p>
</body>
</html>"#;

/// Handler for `GET /`. Returns the static landing page.
pub async fn landing_page() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        HTML,
    )
}
