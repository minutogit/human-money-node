//! Real HTTP browser-origin and DNS-rebinding checks for every private diagnostic route family.
use humoco_node::{
    api::{routes::build_operator_router, AppState},
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    storage::{DualTierEngine, RedbStorage},
};
use std::sync::Arc;

#[tokio::test]
async fn private_http_rejects_foreign_origins_and_rebinding_hosts_but_allows_local_forwarding() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(RedbStorage::open(&temp.path().join("operator.redb")).unwrap());
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tiers = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let state = AppState::new(engine, storage, identity, tiers, pow);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    let done = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, build_operator_router(state))
            .with_graceful_shutdown(async move { done.cancelled().await })
            .await
            .unwrap()
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("http://{addr}");
    for route in [
        "/metrics",
        "/dashboard",
        "/dashboard/data",
        "/dashboard/history",
        "/dashboard/history/hourly",
        "/dashboard/events",
        "/dashboard/vouchers",
        "/peers",
        "/api/v1/network/peers",
        "/health",
        "/health/live",
        "/health/ready",
    ] {
        let url = format!("{base}{route}");
        let local = client.get(&url).send().await.unwrap();
        assert_eq!(local.status(), reqwest::StatusCode::OK, "local CLI {route}");
        assert!(!local.headers().contains_key("access-control-allow-origin"));
        let evil = client
            .get(&url)
            .header("Origin", "https://attacker.example")
            .send()
            .await
            .unwrap();
        assert_eq!(
            evil.status(),
            reqwest::StatusCode::FORBIDDEN,
            "cross-origin {route}"
        );
        assert!(!evil.headers().contains_key("access-control-allow-origin"));
        let rebound = client
            .get(&url)
            .header("Host", "attacker.example:9091")
            .send()
            .await
            .unwrap();
        assert_eq!(
            rebound.status(),
            reqwest::StatusCode::FORBIDDEN,
            "DNS-rebinding Host {route}"
        );
    }
    let url = format!("{base}/metrics");
    let localhost = format!("localhost:{}", addr.port());
    let forwarded_origin = format!("http://{localhost}");
    let same = client
        .get(&url)
        .header("Host", &localhost)
        .header("Origin", &forwarded_origin)
        .header("Sec-Fetch-Site", "same-origin")
        .send()
        .await
        .unwrap();
    assert_eq!(
        same.status(),
        reqwest::StatusCode::OK,
        "SSH-forwarded localhost browser"
    );
    assert!(!same.headers().contains_key("access-control-allow-origin"));
    let ipv6_authority = format!("[::1]:{}", addr.port());
    let ipv6 = client
        .get(&url)
        .header("Host", &ipv6_authority)
        .header("Origin", format!("http://{ipv6_authority}"))
        .header("Sec-Fetch-Site", "same-origin")
        .send()
        .await
        .unwrap();
    assert_eq!(
        ipv6.status(),
        reqwest::StatusCode::OK,
        "IPv6 loopback authority"
    );
    for (host, origin) in [
        (localhost.clone(), "http://localhost:1".to_string()),
        (localhost.clone(), base.clone()),
        (localhost.clone(), "null".to_string()),
        (localhost.clone(), format!("{forwarded_origin}/path")),
        (
            "localhost.attacker.example".into(),
            "http://localhost.attacker.example".into(),
        ),
        ("user@localhost".into(), forwarded_origin.clone()),
    ] {
        let response = client
            .get(&url)
            .header("Host", host)
            .header("Origin", origin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    }
    let cross_site = client
        .get(&url)
        .header("Sec-Fetch-Site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(cross_site.status(), reqwest::StatusCode::FORBIDDEN);
    let preflight = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("Origin", "https://attacker.example")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    assert_eq!(preflight.status(), reqwest::StatusCode::FORBIDDEN);
    stop.cancel();
    server.await.unwrap();
}
