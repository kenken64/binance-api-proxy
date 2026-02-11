use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use bytes::Bytes;
use reqwest::Client;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use std::time::Instant;
use tracing::{debug, error, info, warn};

const BINANCE_API_BASE: &str = "https://api.binance.com";

#[derive(Clone)]
#[allow(dead_code)]
struct AppState {
    client: Client,
    binance_api_key: String,
    binance_api_secret: String,
    proxy_api_key: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "binance_https_proxy=debug".into()),
        )
        .init();

    let proxy_api_key = std::env::var("PROXY_API_KEY").expect("PROXY_API_KEY must be set");
    let binance_api_key =
        std::env::var("BINANCE_API_KEY").expect("BINANCE_API_KEY must be set");
    let binance_api_secret =
        std::env::var("BINANCE_API_SECRET").expect("BINANCE_API_SECRET must be set");
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    let state = Arc::new(AppState {
        client: Client::new(),
        binance_api_key,
        binance_api_secret,
        proxy_api_key,
    });

    // Fetch and log public IP at startup
    match state.client.get("https://api.ipify.org").send().await {
        Ok(resp) => match resp.text().await {
            Ok(ip) => info!("[STARTUP] Public IP address: {}", ip.trim()),
            Err(e) => warn!("[STARTUP] Failed to read public IP response: {}", e),
        },
        Err(e) => warn!("[STARTUP] Failed to fetch public IP: {}", e),
    }

    let app = Router::new()
        .route("/health", any(health))
        .route("/{*path}", any(proxy_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    info!("[STARTUP] Binance HTTPS proxy listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "ok"
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());

    debug!(
        "[INCOMING] {} {} query={:?}",
        method, path, query
    );
    debug!(
        "[INCOMING] Headers: {:?}",
        req.headers()
            .iter()
            .map(|(k, v)| {
                let val = if k.as_str() == "x-proxy-api-key" {
                    "***REDACTED***".to_string()
                } else {
                    v.to_str().unwrap_or("<binary>").to_string()
                };
                (k.as_str().to_string(), val)
            })
            .collect::<Vec<_>>()
    );

    // Skip auth for health check
    if path == "/health" {
        debug!("[AUTH] Skipping auth for health check");
        return Ok(next.run(req).await);
    }

    let api_key = req
        .headers()
        .get("X-Proxy-Api-Key")
        .and_then(|v| v.to_str().ok());

    match api_key {
        Some(key) if key == state.proxy_api_key => {
            debug!("[AUTH] Proxy API key validated for {} {}", method, path);
            Ok(next.run(req).await)
        }
        Some(_) => {
            warn!("[AUTH] Invalid proxy API key for {} {}", method, path);
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            warn!("[AUTH] Missing X-Proxy-Api-Key header for {} {}", method, path);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let start = Instant::now();

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());

    let target_url = format!("{BINANCE_API_BASE}{path_and_query}");

    info!("[PROXY] {} {} -> {}", method, path_and_query, target_url);

    // Log incoming headers (redact sensitive ones)
    debug!("[PROXY] Incoming headers:");
    for (name, value) in headers.iter() {
        let val = match name.as_str() {
            "x-proxy-api-key" | "authorization" => "***REDACTED***".to_string(),
            _ => value.to_str().unwrap_or("<binary>").to_string(),
        };
        debug!("[PROXY]   {}: {}", name, val);
    }

    // Log request body
    if body.is_empty() {
        debug!("[PROXY] Request body: <empty>");
    } else {
        debug!("[PROXY] Request body ({} bytes): {}", body.len(), String::from_utf8_lossy(&body));
    }

    // Build the outgoing request
    let mut req_builder = state.client.request(method.clone(), &target_url);

    // Forward relevant headers (skip hop-by-hop and proxy-specific headers)
    let mut forwarded_headers = Vec::new();
    let mut skipped_headers = Vec::new();
    for (name, value) in headers.iter() {
        match name.as_str() {
            "host" | "x-proxy-api-key" | "connection" | "transfer-encoding" => {
                skipped_headers.push(name.as_str().to_string());
            }
            _ => {
                if let Ok(reqwest_name) = reqwest::header::HeaderName::from_bytes(name.as_ref()) {
                    req_builder = req_builder.header(reqwest_name, value.as_bytes());
                    forwarded_headers.push(name.as_str().to_string());
                }
            }
        }
    }

    debug!("[PROXY] Forwarded headers: {:?}", forwarded_headers);
    debug!("[PROXY] Skipped headers: {:?}", skipped_headers);

    // Inject Binance API key header
    req_builder = req_builder.header("X-MBX-APIKEY", &state.binance_api_key);
    debug!("[PROXY] Injected X-MBX-APIKEY header");

    // Forward request body
    if !body.is_empty() {
        debug!("[PROXY] Forwarding request body ({} bytes)", body.len());
        req_builder = req_builder.body(body);
    }

    debug!("[PROXY] Sending request to Binance...");

    match req_builder.send().await {
        Ok(resp) => {
            let elapsed = start.elapsed();
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

            info!(
                "[RESPONSE] {} {} -> {} ({:.2?})",
                method, path_and_query, status, elapsed
            );

            // Log response headers
            debug!("[RESPONSE] Headers from Binance:");
            for (name, value) in resp.headers().iter() {
                debug!(
                    "[RESPONSE]   {}: {}",
                    name,
                    value.to_str().unwrap_or("<binary>")
                );
            }

            let mut response_headers = HeaderMap::new();
            for (name, value) in resp.headers().iter() {
                match name.as_str() {
                    "transfer-encoding" | "connection" => continue,
                    _ => {
                        if let Ok(axum_name) = header::HeaderName::from_bytes(name.as_ref()) {
                            if let Ok(axum_value) =
                                header::HeaderValue::from_bytes(value.as_bytes())
                            {
                                response_headers.insert(axum_name, axum_value);
                            }
                        }
                    }
                }
            }

            let response_body = resp.bytes().await.unwrap_or_default();

            debug!(
                "[RESPONSE] Body ({} bytes): {}",
                response_body.len(),
                truncate_for_log(&response_body, 1024)
            );

            (status, response_headers, Body::from(response_body)).into_response()
        }
        Err(e) => {
            let elapsed = start.elapsed();
            error!(
                "[RESPONSE] {} {} -> PROXY ERROR ({:.2?}): {}",
                method, path_and_query, elapsed, e
            );
            (StatusCode::BAD_GATEWAY, format!("Proxy error: {e}")).into_response()
        }
    }
}

fn truncate_for_log(bytes: &[u8], max_len: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.len() <= max_len {
        s.into_owned()
    } else {
        format!("{}...<truncated, {} total bytes>", &s[..max_len], bytes.len())
    }
}
