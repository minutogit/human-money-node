//! End-to-end integration and boundary tests for F2F collaboration,
//! Hop-2 topology sensorics, direct operator messaging over QUIC, and WebUI terminology.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::api::auth::AdminTokenManager;
use humoco_node::api::dashboard::{AdminMeshCollabResponse, EnrichedF2fMessageDto};
use humoco_node::api::events::EventLog;
use humoco_node::api::routes::{build_operator_router, AppState};
use humoco_node::identity::NodeIdentity;
use humoco_node::ingress::{PowEngine, TierController};
use humoco_node::network::f2f_collab::F2fMessageDirection;
use humoco_node::network::framing::F2fNeighborRosterPayload;
use humoco_node::network::{DefaultRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, RedbStorage};

fn setup_test_state(identity: NodeIdentity, peer_manager: Arc<PeerManager>) -> AppState {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_collab.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush) = DualTierEngine::new(storage.clone());
    let pow_engine = Arc::new(PowEngine::new(8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let auth = Arc::new(AdminTokenManager::with_token("test_admin_token", false));
    let event_log = Arc::new(EventLog::default());

    let mut state = AppState::new(
        engine,
        storage,
        identity,
        tier_controller,
        pow_engine,
    );
    state.peer_manager = Some(peer_manager);
    state.auth = auth;
    state.event_log = event_log;
    state
}

#[tokio::test]
async fn test_f2f_collab_e2e_quic_roster_and_messaging() {
    // 1. Setup Identities
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let identity_c = NodeIdentity::generate(); // 3rd peer to verify Mutual Consent hiding

    let pk_a = *identity_a.node_pubkey();
    let pk_b = *identity_b.node_pubkey();
    let pk_c = *identity_c.node_pubkey();

    let hex_b = hex::encode(pk_b);

    // 2. Setup PeerManagers
    // Node A has friends: Node B and Node C
    let pm_a = Arc::new(PeerManager::with_f2f(vec![], vec![pk_b, pk_c]));
    pm_a.set_simulation_mode(true);

    // Node B has friend: Node A
    let pm_b = Arc::new(PeerManager::with_f2f(vec![], vec![pk_a]));
    pm_b.set_simulation_mode(true);

    // Node C explicitly opted out of sharing neighbor roster
    pm_a.f2f_collab().lock().roster_mut().record_roster(F2fNeighborRosterPayload {
        sender_pubkey: pk_c,
        timestamp_ms: 1000,
        shares_roster: false,
        visible_neighbors: vec![],
        hidden_neighbor_count: 1,
    });

    // Verify Mutual Consent: Node A's local roster built for Node B hides Node C
    let local_roster_a = pm_a.build_local_f2f_roster(&pk_a).await;
    assert!(local_roster_a.shares_roster);
    assert!(local_roster_a.visible_neighbors.contains(&pk_b));
    assert!(!local_roster_a.visible_neighbors.contains(&pk_c), "Opted-out peer C must be excluded from visible neighbors");
    assert_eq!(local_roster_a.hidden_neighbor_count, 1, "Opted-out peer C must be counted in hidden count");

    // 3. Bind QUIC Transports
    let cancel_a = CancellationToken::new();
    let cancel_b = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    transport_a.spawn_accept_loop();

    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .expect("Bind transport B");
    let addr_b = transport_b.local_addr().expect("local addr B");
    let addr_a = transport_a.local_addr().expect("local addr A");
    transport_b.spawn_accept_loop();

    // Register friend addresses in PeerManager
    pm_a.register_f2f_friend(pk_b, Some(addr_b)).await;
    pm_b.register_f2f_friend(pk_a, Some(addr_a)).await;

    // 4. Connect Node A to Node B over QUIC
    let _conn = transport_a
        .connect_peer(addr_b)
        .await
        .expect("Connect A to B");

    // Give QUIC handshake and F2F session sync a brief moment
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Setup AppState and HTTP Routers
    let mut state_a = setup_test_state(identity_a, pm_a.clone());
    state_a.transport = Some(transport_a.clone());

    let mut state_b = setup_test_state(identity_b, pm_b.clone());
    state_b.transport = Some(transport_b.clone());

    let app_a = build_operator_router(state_a);
    let app_b = build_operator_router(state_b);

    // 6. Node A sends message with trace_pubkeys to Node B via REST endpoint
    let trace_pubkey = [77u8; 32];
    let trace_hex = hex::encode(trace_pubkey);

    let send_body = serde_json::json!({
        "text": "Hallo Nachbar! Bitte prüfe diese auffällige Spur.",
        "trace_pubkeys": [trace_hex.clone()],
        "reply_to_msg_id": null
    });

    let send_req = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/mesh/peers/{}/message", hex_b))
        .header("Authorization", "Bearer test_admin_token")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&send_body).unwrap()))
        .unwrap();

    let send_res = app_a.clone().oneshot(send_req).await.unwrap();
    assert_eq!(send_res.status(), StatusCode::OK);

    let send_bytes = send_res.into_body().collect().await.unwrap().to_bytes();
    let sent_dto: EnrichedF2fMessageDto = serde_json::from_slice(&send_bytes).unwrap();
    assert_eq!(sent_dto.text, "Hallo Nachbar! Bitte prüfe diese auffällige Spur.");
    assert_eq!(sent_dto.peer_pubkey, hex_b);
    assert_eq!(sent_dto.trace_pubkeys, vec![trace_hex.clone()]);
    assert_eq!(sent_dto.direction, F2fMessageDirection::Outbound);

    // 7. Await QUIC transmission, inbound record on Node B, and Ack back to Node A
    let mut received_on_b = false;
    let mut delivered_on_a = false;

    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;

        let b_msgs = pm_b.f2f_collab().lock().inbox().list_messages_for_friend(&pk_a);
        if !b_msgs.is_empty() {
            received_on_b = true;
        }

        let a_msgs = pm_a.f2f_collab().lock().inbox().list_messages_for_friend(&pk_b);
        if a_msgs.iter().any(|m| m.delivered) {
            delivered_on_a = true;
        }

        if received_on_b && delivered_on_a {
            break;
        }
    }

    assert!(received_on_b, "Node B must receive message over QUIC");
    assert!(delivered_on_a, "Node A must receive Ack over QUIC marking delivered == true");

    // 8. Query Node B's GET /dashboard/admin/mesh/collab
    let collab_req = Request::builder()
        .method("GET")
        .uri("/dashboard/admin/mesh/collab")
        .header("Authorization", "Bearer test_admin_token")
        .body(Body::empty())
        .unwrap();

    let collab_res = app_b.oneshot(collab_req).await.unwrap();
    assert_eq!(collab_res.status(), StatusCode::OK);

    let collab_bytes = collab_res.into_body().collect().await.unwrap().to_bytes();
    let collab_dto: AdminMeshCollabResponse = serde_json::from_slice(&collab_bytes).unwrap();

    assert!(collab_dto.share_neighbor_roster);
    assert!(!collab_dto.messages.is_empty());

    let inbound_msg = &collab_dto.messages[0];
    assert_eq!(inbound_msg.direction, F2fMessageDirection::Inbound);
    assert_eq!(inbound_msg.text, "Hallo Nachbar! Bitte prüfe diese auffällige Spur.");
    assert_eq!(inbound_msg.trace_pubkeys, vec![trace_hex.clone()]);
    assert!(inbound_msg.trace_analysis.is_some(), "Inbound message with trace pubkeys must be enriched with trace_analysis");

    cancel_a.cancel();
    cancel_b.cancel();
}

#[tokio::test]
async fn test_f2f_collab_auth_boundary() {
    let identity = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::with_f2f(vec![], vec![]));
    let state = setup_test_state(identity, pm);
    let app = build_operator_router(state);

    // 1. GET /dashboard/admin/mesh/collab without token -> 401
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/admin/mesh/collab")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 2. GET with invalid token -> 401
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/admin/mesh/collab")
                .header("Authorization", "Bearer invalid_secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 3. POST /dashboard/admin/mesh/peers/:key/message without token -> 401
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/admin/mesh/peers/aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344/message")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"text":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 4. POST /dashboard/admin/mesh/trace-analyze without token -> 401
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/admin/mesh/trace-analyze")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"pubkeys":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 5. Authorized GET -> 200
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/admin/mesh/collab")
                .header("Authorization", "Bearer test_admin_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_f2f_collab_input_validation_and_control_chars() {
    let identity = NodeIdentity::generate();
    let friend_pk = [55u8; 32];
    let friend_hex = hex::encode(friend_pk);

    let pm = Arc::new(PeerManager::with_f2f(vec![], vec![friend_pk]));
    let state = setup_test_state(identity, pm);
    let app = build_operator_router(state);

    let send_url = format!("/dashboard/admin/mesh/peers/{}/message", friend_hex);

    // 1. Control character rejection (\x07 bell or \x00 null)
    let body_ctrl = serde_json::json!({
        "text": "Hello\x07world",
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&send_url)
                .header("Authorization", "Bearer test_admin_token")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body_ctrl).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 2. Empty text rejection
    let body_empty = serde_json::json!({
        "text": "   ",
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&send_url)
                .header("Authorization", "Bearer test_admin_token")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body_empty).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 3. Oversized text rejection (> 500 chars)
    let body_oversized = serde_json::json!({
        "text": "a".repeat(501),
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&send_url)
                .header("Authorization", "Bearer test_admin_token")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body_oversized).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 4. Too many trace pubkeys (> 32)
    let too_many_keys: Vec<String> = (0..33).map(|i| hex::encode([i as u8; 32])).collect();
    let body_too_many_traces = serde_json::json!({
        "text": "Checking too many traces",
        "trace_pubkeys": too_many_keys
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&send_url)
                .header("Authorization", "Bearer test_admin_token")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body_too_many_traces).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 5. Allowed control chars (newlines and tabs)
    let body_newline_tab = serde_json::json!({
        "text": "Line 1\nLine 2\tTabbed",
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&send_url)
                .header("Authorization", "Bearer test_admin_token")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body_newline_tab).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_dashboard_html_knotenfreunde_terminology() {
    let identity = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::with_f2f(vec![], vec![]));
    let state = setup_test_state(identity, pm);
    let app = build_operator_router(state);

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Strict terminology checks
    assert!(body_str.contains("Knotenfreunde"), "Must contain Knotenfreunde");
    assert!(body_str.contains("Knotenfreund"), "Must contain Knotenfreund");
    assert!(!body_str.contains("F2F Friend"), "Must NOT contain old F2F Friend role label");
    assert!(body_str.contains("Bevorzugte Kassen"), "Must use unambiguous Kassen label in tab-access");
}
