// Audit-only instrumentation: preserve real TLS, framing, handlers and vote checks.
static AUDIT_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static AUDIT_ALTERNATIVE: std::sync::Mutex<Option<L2LockEntry>> = std::sync::Mutex::new(None);
struct AuditDelayHandler { inner: Arc<NodeRequestHandler>, index: usize }
impl humoco_node::network::RequestHandler for AuditDelayHandler {
    fn handle_authenticated(&self, h: humoco_sim_core::wire::WireHeader, p: Vec<u8>, peer: Option<[u8;32]>) -> humoco_node::network::transport::BoxFuture<Result<(humoco_sim_core::wire::WireHeader, Vec<u8>), humoco_node::NodeError>> {
        let inner = self.inner.clone();
        let index = self.index;
        Box::pin(async move {
            use humoco_sim_core::wire::{MsgType, WireHeader};
            let mode = AUDIT_MODE.load(std::sync::atomic::Ordering::SeqCst);
            if mode == 1 && (h.msg_type == MsgType::StatusQuery as u16 || h.msg_type == MsgType::LiveStateRequest as u16) {
                tokio::time::sleep(std::time::Duration::from_millis(450)).await;
            }
            if mode == 3 && h.msg_type == MsgType::LockVerifyRequest as u16 {
                let entry = AUDIT_ALTERNATIVE.lock().unwrap().clone().unwrap();
                let bytes = bincode::serialize(&entry).unwrap();
                let decoded: L2LockEntry = bincode::deserialize(&bytes).unwrap();
                assert_eq!(entry, decoded);
                return Ok((WireHeader::new(MsgType::LockVerifyResponse as u16,h.session_seq+1,0,humoco_sim_core::wire::FLAG_COLLISION_DETECTED,bytes.len() as u32),bytes));
            }
            if mode == 2 && h.msg_type == MsgType::StatusQuery as u16 {
                if index == 0 {
                    let entry = AUDIT_ALTERNATIVE.lock().unwrap().clone().unwrap();
                    let bytes = serde_json::to_vec(&entry).unwrap();
                    return Ok((WireHeader::new(MsgType::StatusResponse as u16, h.session_seq+1,0,0,bytes.len() as u32),bytes));
                }
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
            humoco_node::network::RequestHandler::handle_authenticated(inner.as_ref(),h,p,peer).await
        })
    }
}
async fn audit_remote_context(cluster: &LiveProofCluster) -> LiveStateContext {
    let mut context = cluster.context.clone();
    let owner = SigningKey::from_bytes(&[77;32]);
    let tag = "audit-remote-only";
    let now = cluster.shards[0].pm.net_time_ms();
    let req = make_hmc_spend(&context.voucher_id,tag,[0xCC;32],now+800_000,&owner);
    for shard in &cluster.shards {
        let (v,_) = shard.engine.ingress_hmc_lock_durable(tag.into(),L2LockEntry::from(&req),humoco_node::storage::IngressOrigin::PartitionSync,Some(now),None,None,Some(context.voucher_id.clone())).await;
        assert!(matches!(v,L2Verdict::Verified {..}));
        shard.ready.mark_shard_ready(context.shard_id);
    }
    let alternative = make_hmc_spend(&context.voucher_id,tag,[0xDD;32],now+800_000,&owner);
    *AUDIT_ALTERNATIVE.lock().unwrap() = Some(L2LockEntry::from(&alternative));
    context.lookup_tag = tag.into();
    context.parent_lock = *blake3::hash(tag.as_bytes()).as_bytes();
    context.child_lock = [0xBB;32];
    context.state_digest = [0xBB;32];
    context
}
async fn audit_live_request(cluster: &LiveProofCluster, context: &LiveStateContext) -> axum::response::Response {
    cluster.app.clone().oneshot(Request::builder().method("POST").uri("/v1/verify-current").header("content-type","application/json").body(axum::body::Body::from(serde_json::to_vec(context).unwrap())).unwrap()).await.unwrap()
}
fn audit_cleanup(cluster: LiveProofCluster) {
    cluster.cancel.cancel(); cluster.gateway_transport.close();
    for shard in cluster.shards { shard.transport.close(); }
    AUDIT_MODE.store(0,std::sync::atomic::Ordering::SeqCst);
}
#[tokio::test]
async fn audit_probe_two_independent_budgets_exceed_800ms() {
    let temp = tempdir().unwrap();
    let cluster = setup_live_proof_cluster(&temp).await;
    let context = audit_remote_context(&cluster).await;
    AUDIT_MODE.store(1,std::sync::atomic::Ordering::SeqCst);
    let start = std::time::Instant::now();
    let response = audit_live_request(&cluster,&context).await;
    let elapsed = start.elapsed();
    assert_eq!(response.status(),StatusCode::OK);
    assert!(elapsed > std::time::Duration::from_millis(850));
    println!("OBSERVED: valid 14/20 live proof after {} ms (450 ms discovery + 450 ms voting)",elapsed.as_millis());
    audit_cleanup(cluster);
}
#[tokio::test]
async fn audit_probe_first_minority_answer_blocks_nineteen_agreeing_nodes() {
    let temp = tempdir().unwrap();
    let cluster = setup_live_proof_cluster(&temp).await;
    let context = audit_remote_context(&cluster).await;
    AUDIT_MODE.store(2,std::sync::atomic::Ordering::SeqCst);
    let response = audit_live_request(&cluster,&context).await;
    assert_eq!(response.status(),StatusCode::SERVICE_UNAVAILABLE);
    AUDIT_MODE.store(0,std::sync::atomic::Ordering::SeqCst);
    let response = audit_live_request(&cluster,&context).await;
    assert_eq!(response.status(),StatusCode::OK);
    println!("OBSERVED: one fast alternative signed child causes 503; same cluster without alternative returns 200");
    audit_cleanup(cluster);
}

#[tokio::test]
async fn audit_probe_wire_collision_becomes_http_503() {
    let temp = tempdir().unwrap();
    let cluster = setup_live_proof_cluster(&temp).await;
    let context = audit_remote_context(&cluster).await;
    let owner = SigningKey::from_bytes(&[77;32]);
    let mut req = make_hmc_spend(&context.voucher_id,&context.lookup_tag,[0xEE;32],cluster.shards[0].pm.net_time_ms()+800_000,&owner);
    req.created_at_ms = cluster.shards[0].pm.net_time_ms();
    req.layer2_signature = owner.sign(&calculate_l2_payload_hash(&req)).to_bytes();
    let existing = AUDIT_ALTERNATIVE.lock().unwrap().clone().unwrap();
    assert!(humoco_node::api::hmc::verify_l2_lock_entry_signature(&existing,&context.lookup_tag));
    AUDIT_MODE.store(3,std::sync::atomic::Ordering::SeqCst);
    let response = cluster.app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock").header("content-type","application/json").header("X-Peer-Token","audit24_token").body(axum::body::Body::from(serde_json::to_vec(&req).unwrap())).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let envelope: L2ResponseEnvelope = serde_json::from_slice(&bytes).unwrap();
    println!("OBSERVED: all remotes return collision flag and valid signed lock; HTTP {status}, verdict {:?}",envelope.verdict);
    assert_eq!(status,StatusCode::SERVICE_UNAVAILABLE);
    assert!(matches!(envelope.verdict,L2Verdict::Rejected { .. }));
    audit_cleanup(cluster);
}
