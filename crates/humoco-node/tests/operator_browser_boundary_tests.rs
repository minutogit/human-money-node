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

#[tokio::test]
async fn signed_regional_view_is_private_and_matches_real_committee_selection() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(RedbStorage::open(&temp.path().join("regional.redb")).unwrap());
    let stop = tokio_util::sync::CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(storage.clone(), stop.clone());
    let identity = NodeIdentity::generate();
    let manager = Arc::new(humoco_node::network::PeerManager::new(Vec::new()));
    // Isolated eligibility fixture, not a proof of admission or the fault bound.
    for _ in 0..20 {
        let member = NodeIdentity::generate();
        manager.learn_node_from_gossip_with_hrw(*member.node_pubkey(), *member.hrw_routing_id(), "127.0.0.1:1".parse().unwrap(), 0, None).await;
        manager.set_first_seen_for_test(member.node_pubkey(), std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
    }
    let immature = NodeIdentity::generate();
    manager.learn_node_from_gossip_with_hrw(*immature.node_pubkey(), *immature.hrw_routing_id(), "127.0.0.1:1".parse().unwrap(), 0, None).await;
    let (expected, _, _) = manager.shard_committee(*identity.node_pubkey(), *identity.hrw_routing_id(), 42).await;
    let pow = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tiers = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let mut state = AppState::new(engine, storage, identity.clone(), tiers, pow);
    state.peer_manager = Some(manager.clone());
    let public_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public_listener.local_addr().unwrap();
    let private_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let private_addr = private_listener.local_addr().unwrap();
    let public_cancel = stop.clone(); let private_cancel = stop.clone();
    let public = humoco_node::api::build_router(state.clone());
    let private = build_operator_router(state);
    let a = tokio::spawn(async move { axum::serve(public_listener, public).with_graceful_shutdown(async move {public_cancel.cancelled().await}).await.unwrap(); });
    let b = tokio::spawn(async move { axum::serve(private_listener, private).with_graceful_shutdown(async move {private_cancel.cancelled().await}).await.unwrap(); });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let path = "/v1/operator/regional-mesh-view";
    assert_eq!(client.get(format!("http://{public_addr}{path}")).send().await.unwrap().status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(client.get(format!("http://{private_addr}{path}")).header("Origin","https://evil.example").send().await.unwrap().status(), reqwest::StatusCode::FORBIDDEN);
    let view: humoco_proto::mesh::RegionalMeshView = client.get(format!("http://{private_addr}{path}")).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    assert!(!view.members.iter().any(|m| m.node_pubkey == *immature.node_pubkey()));
    let policy = humoco_proto::mesh::RegionalMeshPolicy { network:0, source_keys:vec![*identity.node_pubkey()] };
    let roster = humoco_proto::mesh::regional_committee(&policy,&[view],42,manager.net_time_ms()).unwrap();
    assert_eq!(roster,expected.into_iter().map(|m|m.node_pubkey).collect::<Vec<_>>());
    stop.cancel(); a.await.unwrap(); b.await.unwrap(); worker.await.unwrap();
}
