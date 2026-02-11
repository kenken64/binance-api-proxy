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
use tracing::{error, info};

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
                .unwrap_or_else(|_| "binance_https_proxy=info".into()),
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
    info!("Binance HTTPS proxy listening on {addr}");

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
    // Skip auth for health check
    if req.uri().path() == "/health" {
        return Ok(next.run(req).await);
    }

    let api_key = req
        .headers()
        .get("X-Proxy-Api-Key")
        .and_then(|v| v.to_str().ok());

    match api_key {
        Some(key) if key == state.proxy_api_key => Ok(next.run(req).await),
        _ => {
            error!("Unauthorized request to {}", req.uri().path());
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
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());

    let target_url = format!("{BINANCE_API_BASE}{path_and_query}");

    info!("{method} {path_and_query} -> {target_url}");

    // Build the outgoing request
    let mut req_builder = state.client.request(method, &target_url);

    // Forward relevant headers (skip hop-by-hop and proxy-specific headers)
    for (name, value) in headers.iter() {
        match name.as_str() {
            "host" | "x-proxy-api-key" | "connection" | "transfer-encoding" => continue,
            _ => {
                if let Ok(reqwest_name) = reqwest::header::HeaderName::from_bytes(name.as_ref()) {
                    req_builder = req_builder.header(reqwest_name, value.as_bytes());
                }
            }
        }
    }

    // Inject Binance API key header
    req_builder = req_builder.header("X-MBX-APIKEY", &state.binance_api_key);

    // Forward request body
    if !body.is_empty() {
        req_builder = req_builder.body(body);
    }

    match req_builder.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

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

            (status, response_headers, Body::from(response_body)).into_response()
        }
        Err(e) => {
            error!("Proxy error: {e}");
            (StatusCode::BAD_GATEWAY, format!("Proxy error: {e}")).into_response()
        }
    }
}
