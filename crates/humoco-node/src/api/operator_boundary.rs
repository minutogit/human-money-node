//! Browser boundary for private operator HTTP: loopback binding alone does not prevent DNS rebinding.
use axum::{
    extract::Request,
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

fn loopback_authority(raw: &str, scheme: &str) -> Option<(String, u16)> {
    if raw.is_empty()
        || raw.len() > 512
        || !raw.is_ascii()
        || raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b"@/\\?#".contains(&b))
    {
        return None;
    }
    let url = reqwest::Url::parse(&format!("{scheme}://{raw}/")).ok()?;
    let host = url
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']');
    if !host.eq_ignore_ascii_case("localhost")
        && !host.parse::<std::net::IpAddr>().ok()?.is_loopback()
    {
        return None;
    }
    Some((host.to_ascii_lowercase(), url.port_or_known_default()?))
}

fn allowed(headers: &HeaderMap) -> bool {
    // Repeated authority/origin values are ambiguous and never needed by a browser.
    if headers.get_all(header::HOST).iter().count() > 1
        || headers.get_all(header::ORIGIN).iter().count() > 1
    {
        return false;
    }
    let host = match headers.get(header::HOST) {
        Some(value) => match value.to_str() {
            Ok(value) if loopback_authority(value, "http").is_some() => Some(value),
            _ => return false,
        },
        None => None, // Internal router tests and HTTP/1.0 CLI requests may omit Host.
    };
    if let Some(site) = headers.get("sec-fetch-site") {
        match site.to_str() {
            Ok("same-origin" | "none") => {}
            _ => return false,
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let Some(host) = host else {
            return false;
        };
        let Ok(raw) = origin.to_str() else {
            return false;
        };
        if raw.len() > 1024 {
            return false;
        }
        let Ok(url) = reqwest::Url::parse(raw) else {
            return false;
        };
        if !matches!(url.scheme(), "http" | "https") || url.origin().ascii_serialization() != raw {
            return false;
        }
        let Some(origin_authority) = raw.split_once("://").map(|(_, authority)| authority) else {
            return false;
        };
        if loopback_authority(host, url.scheme())
            != loopback_authority(origin_authority, url.scheme())
        {
            return false;
        }
    }
    true
}

/// Rejects foreign browser origins and rebinding authorities before serving any private alias.
/// CLI requests without browser headers remain usable on the loopback-only listener.
pub async fn enforce_operator_browser_boundary(request: Request, next: Next) -> Response {
    if !allowed(request.headers()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}
