//! End-to-end integration and boundary tests for F2F collaboration,
//! Hop-2 topology sensorics, direct operator messaging over QUIC, and WebUI terminology.

use std::future::Future;
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
use humoco_node::network::framing::{F2fNeighborRosterPayload, F2fOperatorMessageAckPayload};
use humoco_node::network::{DefaultRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, RedbStorage};
use humoco_sim_core::{MsgType, WireHeader};

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

async fn check_quic_roster_receipt(
    candidate_count: usize,
) -> Option<F2fNeighborRosterPayload> {
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let pk_a = *identity_a.node_pubkey();
    let pk_b = *identity_b.node_pubkey();

    let other_friends: Vec<[u8; 32]> = (0..candidate_count.saturating_sub(1))
        .map(|_| *NodeIdentity::generate().node_pubkey())
        .collect();

    let mut a_friends = vec![pk_b];
    a_friends.extend_from_slice(&other_friends);

    let pm_a = Arc::new(PeerManager::with_f2f(vec![], a_friends.clone()));
    pm_a.set_simulation_mode(true);

    let pm_b = Arc::new(PeerManager::with_f2f(vec![], vec![pk_a]));
    pm_b.set_simulation_mode(true);

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

    pm_a.register_f2f_friend(pk_b, Some(addr_b)).await;
    pm_b.register_f2f_friend(pk_a, Some(addr_a)).await;
    for friend_pk in &other_friends {
        pm_a.register_f2f_friend(*friend_pk, None).await;
    }

    let _conn = transport_a.connect_peer(addr_b).await.expect("Connect A to B");

    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        if let Some(r) = pm_b.f2f_collab().lock().roster().get_roster(&pk_a) {
            received = Some(r.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    cancel_a.cancel();
    cancel_b.cancel();
    received
}

#[tokio::test]
async fn test_s04_18_f2f_roster_real_quic_boundary_exchange() {
    // 62 candidates -> remote peer receives roster with 62 visible and 0 hidden
    let roster_62 = check_quic_roster_receipt(62)
        .await
        .expect("remote peer must receive roster for 62 candidates");
    assert_eq!(roster_62.visible_neighbors.len(), 62);
    assert_eq!(roster_62.hidden_neighbor_count, 0);

    // 63 candidates -> remote peer receives roster with 62 visible and 1 hidden
    let roster_63 = check_quic_roster_receipt(63)
        .await
        .expect("remote peer must receive roster for 63 candidates");
    assert_eq!(roster_63.visible_neighbors.len(), 62);
    assert_eq!(roster_63.hidden_neighbor_count, 1);

    // 64 candidates -> remote peer receives roster with 62 visible and 2 hidden
    let roster_64 = check_quic_roster_receipt(64)
        .await
        .expect("remote peer must receive roster for 64 candidates");
    assert_eq!(roster_64.visible_neighbors.len(), 62);
    assert_eq!(roster_64.hidden_neighbor_count, 2);
}

// =========================================================================
// S04-19 Regressions: Bookkeeping-order, peer visibility, ACK before send,
// failed send, cancellation, and reconnect controls over QUIC.
// =========================================================================

#[test]
fn test_s04_19_f2f_bookkeeping_order_store_regression() {
    let mut store = humoco_node::network::f2f_collab::F2fInboxStore::new(None);
    let friend_pk = [42u8; 32];
    let msg_id = 1001u64;

    let payload = humoco_node::network::framing::F2fOperatorMessagePayload {
        msg_id,
        sender_pubkey: [1u8; 32],
        timestamp_ms: 50_000,
        text: "Bookkeeping order probe".into(),
        trace_pubkeys: vec![],
        reply_to_msg_id: None,
    };

    // Defect interleaving: ACK arrives before sender publishes to outbox/history
    let ack_result = store.on_ack_received(friend_pk, msg_id);
    assert!(!ack_result, "Unmatched ACK must return false when record is missing");

    // Sender subsequently calls queue_outbound(..., false)
    let stored_defect = store.queue_outbound(friend_pk, payload.clone(), false);
    assert!(
        !stored_defect.delivered,
        "Defect interleaving produces delivered=false"
    );
    assert!(
        store.get_pending_outbox(&friend_pk).is_some(),
        "Defect interleaving leaves acknowledged message pending in outbox"
    );

    // Correct contract trace (S04-19): sender publishes FIRST, then ACK arrives
    let mut store_correct = humoco_node::network::f2f_collab::F2fInboxStore::new(None);
    let stored_initial = store_correct.queue_outbound(friend_pk, payload.clone(), false);
    assert!(!stored_initial.delivered);
    assert!(store_correct.get_pending_outbox(&friend_pk).is_some());

    let ack_success = store_correct.on_ack_received(friend_pk, msg_id);
    assert!(ack_success, "Authenticated ACK must match published pending record");
    assert!(
        store_correct.get_pending_outbox(&friend_pk).is_none(),
        "Authenticated ACK must clear pending outbox slot"
    );
    let history = store_correct.list_messages_for_friend(&friend_pk);
    assert_eq!(history.len(), 1);
    assert!(
        history[0].delivered,
        "Stored message must be marked delivered=true"
    );

    // Bounded exact-ID check: an ACK for an old ID must NOT clear a different pending message
    let payload_next = humoco_node::network::framing::F2fOperatorMessagePayload {
        msg_id: 1002u64,
        sender_pubkey: [1u8; 32],
        timestamp_ms: 51_000,
        text: "Next pending message".into(),
        trace_pubkeys: vec![],
        reply_to_msg_id: None,
    };
    store_correct.queue_outbound(friend_pk, payload_next, false);
    let stale_ack = store_correct.on_ack_received(friend_pk, 9999u64);
    assert!(!stale_ack);
    assert_eq!(
        store_correct.get_pending_outbox(&friend_pk).unwrap().msg_id,
        1002u64,
        "Pending outbox must only be cleared by exact matching msg_id"
    );
}

struct TestNoopWaker;
impl std::task::Wake for TestNoopWaker {
    fn wake(self: std::sync::Arc<Self>) {}
}

#[tokio::test]
async fn test_s04_19_real_quic_peer_visibility_and_ack_barrier() {
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let pk_a = *identity_a.node_pubkey();
    let pk_b = *identity_b.node_pubkey();

    let pm_a = Arc::new(PeerManager::with_f2f(vec![], vec![pk_b]));
    pm_a.set_simulation_mode(true);

    let pm_b = Arc::new(PeerManager::with_f2f(vec![], vec![pk_a]));
    pm_b.set_simulation_mode(true);

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

    pm_a.register_f2f_friend(pk_b, Some(addr_b)).await;
    pm_b.register_f2f_friend(pk_a, Some(addr_a)).await;

    let _conn_a = transport_a.connect_peer(addr_b).await.expect("Connect A to B");

    // Wait until peer manager registers the live connection
    let mut connected = false;
    for _ in 0..50 {
        if pm_a.get_connection(&addr_b).await.is_some() {
            connected = true;
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(connected, "QUIC connection between A and B must be active");

    // Reverse connection from B to A for bidirectional QUIC frames
    let conn_b_to_a = transport_b.connect_peer(addr_a).await.expect("Connect B to A");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // =========================================================================
    // Contract Check 1: Pre-send flight invariant (pre-await publishing)
    // Hold write lock on pm_a's peers to pause send_f2f_operator_message during connection lookup.
    // In fixed code (S04-19): sender publishes pending/history record BEFORE connection lookup.
    // In buggy code: sender defers publishing until AFTER transmission completes.
    // =========================================================================
    let peers_guard = pm_a.acquire_peers_write_lock_for_test().await;

    let t_a = transport_a.clone();
    let mut send_fut = Box::pin(t_a.send_f2f_operator_message(pk_b, "barrier message".into(), vec![], None));

    let waker = std::sync::Arc::new(TestNoopWaker).into();
    let mut cx = std::task::Context::from_waker(&waker);
    let poll_res = send_fut.as_mut().poll(&mut cx);
    assert!(
        poll_res.is_pending(),
        "send_f2f_operator_message must yield at connection lookup"
    );

    // Inspect Node A's store while connection lookup is paused:
    let pending_during_flight = pm_a.f2f_collab().lock().inbox().get_pending_outbox(&pk_b).cloned();
    let history_during_flight = pm_a.f2f_collab().lock().inbox().list_messages_for_friend(&pk_b);

    assert!(
        pending_during_flight.is_some(),
        "Defect detected: sender has no pending outbox record before connection lookup/transmission"
    );
    let in_flight_msg_id = pending_during_flight.unwrap().msg_id;
    assert!(
        !history_during_flight.is_empty(),
        "Defect detected: sender has no history record before connection lookup/transmission"
    );
    assert_eq!(
        history_during_flight[0].msg_id,
        in_flight_msg_id,
        "History record must match the in-flight message ID"
    );

    // =========================================================================
    // Contract Check 2: Real QUIC ACK barrier before sender completion
    // While send_fut is still paused before completion, Node B sends an authenticated
    // F2fOperatorMessageAck for this exact msg_id over real QUIC to Node A.
    // =========================================================================
    let ack_payload = F2fOperatorMessageAckPayload {
        msg_id: in_flight_msg_id,
        receiver_pubkey: pk_b,
        timestamp_ms: pm_b.net_time_ms(),
    };
    let ack_bytes = ack_payload.to_bytes().expect("serialize ack");
    let ack_hdr = WireHeader::new(
        MsgType::F2fOperatorMessageAck as u16,
        0,
        0,
        0,
        ack_bytes.len() as u32,
    );
    transport_b
        .send_unidirectional(&conn_b_to_a, &ack_hdr, &ack_bytes)
        .await
        .expect("send ack over QUIC");

    // Wait until Node A's accept loop processes the ACK
    let mut ack_processed = false;
    for _ in 0..50 {
        let a_msgs = pm_a.f2f_collab().lock().inbox().list_messages_for_friend(&pk_b);
        let a_pending_cleared = pm_a.f2f_collab().lock().inbox().get_pending_outbox(&pk_b).is_none();
        if a_pending_cleared && a_msgs.iter().any(|m| m.msg_id == in_flight_msg_id && m.delivered) {
            ack_processed = true;
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(ack_processed, "Node A must process authentic QUIC ACK and mark delivered=true");

    // Release peers lock and resume send_fut:
    drop(peers_guard);

    let send_result = send_fut.await.expect("send_f2f_operator_message ok");

    // Contract: sender must NOT overwrite delivered=true with a stale undelivered clone!
    assert!(
        send_result.delivered,
        "send_f2f_operator_message must return delivered=true when ACK already processed"
    );
    assert_eq!(send_result.msg_id, in_flight_msg_id);
    assert!(
        pm_a.f2f_collab().lock().inbox().get_pending_outbox(&pk_b).is_none(),
        "No pending outbox slot must remain after delivery ACK"
    );

    cancel_a.cancel();
    cancel_b.cancel();
}

#[tokio::test]
async fn test_s04_19_f2f_cancellation_failed_send_and_reconnect() {
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let pk_a = *identity_a.node_pubkey();
    let pk_b = *identity_b.node_pubkey();

    let pm_a = Arc::new(PeerManager::with_f2f(vec![], vec![pk_b]));
    pm_a.set_simulation_mode(true);

    let cancel_a = CancellationToken::new();
    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    transport_a.spawn_accept_loop();

    // 1. Cancellation control:
    // Calling send_f2f_operator_message must publish to outbox synchronously before awaiting network.
    // If the future is cancelled after first poll (before completion), the record must already exist in store.
    let cancel_friend = [77u8; 32];
    pm_a.register_f2f_friend(cancel_friend, Some("127.0.0.1:12345".parse().unwrap())).await;

    let peers_guard = pm_a.acquire_peers_write_lock_for_test().await;
    let t_a = transport_a.clone();
    let mut send_fut = Box::pin(t_a.send_f2f_operator_message(cancel_friend, "cancellation test message".into(), vec![], None));

    let waker = std::sync::Arc::new(TestNoopWaker).into();
    let mut cx = std::task::Context::from_waker(&waker);
    let poll_res = send_fut.as_mut().poll(&mut cx);
    assert!(
        poll_res.is_pending(),
        "send_f2f_operator_message must yield at connection lookup"
    );

    // Cancel future before completion:
    drop(send_fut);
    drop(peers_guard);

    let a_pending = pm_a.f2f_collab().lock().inbox().get_pending_outbox(&cancel_friend).cloned();
    let a_history = pm_a.f2f_collab().lock().inbox().list_messages_for_friend(&cancel_friend);
    assert!(
        a_pending.is_some(),
        "Message must be published to pending outbox before await (cancellation resilience)"
    );
    assert!(
        !a_history.is_empty(),
        "Message must be published to history before await (cancellation resilience)"
    );

    // 2. Failed / offline send control:
    // If friend has no known address or connection, send_f2f_operator_message completes with
    // delivered=false, retaining the message in pending outbox for reconnect.
    let offline_friend = [88u8; 32];
    pm_a.register_f2f_friend(offline_friend, None).await;

    let res_offline = transport_a
        .send_f2f_operator_message(offline_friend, "offline message".into(), vec![], None)
        .await
        .expect("offline send should succeed in queueing");
    assert!(!res_offline.delivered, "Offline message must not be marked delivered");
    let offline_pending = pm_a.f2f_collab().lock().inbox().get_pending_outbox(&offline_friend).cloned();
    assert!(offline_pending.is_some(), "Offline message must remain in pending outbox");
    assert_eq!(offline_pending.unwrap().msg_id, res_offline.msg_id);

    // 3. Reconnect control over real QUIC:
    // Now offline_friend (Node C) comes online and connects to Node A.
    let identity_c = NodeIdentity::generate();
    let pk_c = *identity_c.node_pubkey();
    // Register pk_c as friend on A:
    pm_a.register_f2f_friend(pk_c, None).await;

    let queued_for_c = transport_a
        .send_f2f_operator_message(pk_c, "queued for reconnect".into(), vec![], None)
        .await
        .expect("queue for c ok");
    assert!(!queued_for_c.delivered);
    assert!(pm_a.f2f_collab().lock().inbox().get_pending_outbox(&pk_c).is_some());

    // Node C binds and connects to Node A
    let pm_c = Arc::new(PeerManager::with_f2f(vec![], vec![pk_a]));
    pm_c.set_simulation_mode(true);
    let cancel_c = CancellationToken::new();
    let transport_c = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_c,
        pm_c.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_c.clone(),
    )
    .expect("Bind transport C");
    let addr_c = transport_c.local_addr().expect("local addr C");
    let addr_a = transport_a.local_addr().expect("local addr A");
    transport_c.spawn_accept_loop();

    pm_a.register_f2f_friend(pk_c, Some(addr_c)).await;
    pm_c.register_f2f_friend(pk_a, Some(addr_a)).await;

    let conn_a_to_c = transport_a.connect_peer(addr_c).await.expect("A connects to C");

    // Flush session outbox on connect (as done on reconnect)
    transport_a.sync_f2f_friend_session(pk_c, (*conn_a_to_c).clone()).await;

    // Await delivery on C and ACK processing on A
    let mut delivered_on_reconnect = false;
    for _ in 0..50 {
        let c_msgs = pm_c.f2f_collab().lock().inbox().list_messages_for_friend(&pk_a);
        let a_pending_c_none = pm_a.f2f_collab().lock().inbox().get_pending_outbox(&pk_c).is_none();
        let a_msgs_c = pm_a.f2f_collab().lock().inbox().list_messages_for_friend(&pk_c);

        if !c_msgs.is_empty() && a_pending_c_none && a_msgs_c.iter().any(|m| m.delivered) {
            delivered_on_reconnect = true;
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(delivered_on_reconnect, "Pending outbox message must be delivered and acknowledged on reconnect");

    cancel_a.cancel();
    cancel_c.cancel();
}
