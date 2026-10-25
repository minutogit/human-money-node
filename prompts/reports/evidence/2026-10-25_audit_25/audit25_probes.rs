use std::sync::Arc;
use ed25519_dalek::Signer;
use humoco_node::{api::{build_router,hmc::*,AppState},identity::NodeIdentity,ingress::{PowEngine,TierController},storage::{DualTierEngine,RedbStorage}};
use sha3::{Digest,Sha3_256};
use humoco_node::ingress::pow::{compute_stateless_challenge,compute_solution_hash,count_leading_zero_bits};
fn make_root_request(author: &NodeIdentity, voucher: &str, now: u64) -> L2LockRequest {
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: *author.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: voucher.into(),
        ds_tag: None,
        transaction_hash: [42; 32],
        is_genesis: true,
        sender_ephemeral_pub: *author.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 42,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    };
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: voucher.into(),
        transaction_id: req.transaction_hash,
        state_hash: req.transaction_hash,
        sender_pubkey: *author.node_pubkey(),
        receiver_pubkey_hash: Some(Sha3_256::digest(author.node_pubkey()).into()),
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = author.signing_key().sign(&proof.digest().unwrap()).to_bytes();
    req.causal_output = Some(proof);
    req.layer2_signature = author.signing_key().sign(&calculate_l2_payload_hash(&req)).to_bytes();
    req
}


#[tokio::test]
async fn a25_canonical_direct_work_is_rejected() {
 let engine=PowEngine::new([1;32],8); let parent=[2;32]; let now=6000; let slot=now/600;
 let challenge=compute_stateless_challenge(&parent,slot);
 let nonce=(0u64..1_000_000).find(|nonce| {
  let mut h=blake3::Hasher::new(); let tag=b"HUMOCO_V1_POW_STATELESS";
  h.update(&[tag.len() as u8]); h.update(tag);h.update(&parent);h.update(&slot.to_le_bytes());h.update(&nonce.to_le_bytes());
  count_leading_zero_bits(h.finalize().as_bytes())>=8 && count_leading_zero_bits(&compute_solution_hash(&challenge,*nonce))<8
 }).unwrap();
 let result=engine.verify_pow_for_parent_at(&hex::encode(challenge),nonce,8,Some(&parent),now).await;
 println!("canonical nonce={nonce}; production={result:?}"); assert!(result.is_err());
}
#[tokio::test]
async fn a25_exact_work_retry_rejected_and_generic_work_transplants() {
 let engine=PowEngine::new([1;32],4);let now=6000;
 let (generic,diff,_)=engine.generate_challenge_for_parent_at(&[0;32],now);
 let nonce=PowEngine::solve_pow(&generic,diff,100000).unwrap();
 assert_eq!(engine.verify_pow_for_parent_at(&generic,nonce,diff,Some(&[2;32]),now).await,Ok(true));
 let result=engine.verify_pow_for_parent_at(&generic,nonce,diff,Some(&[2;32]),now).await;
 println!("exact retry={result:?}");assert!(matches!(result,Err(humoco_node::ingress::PowError::ReplayDetected)));
 let other=PowEngine::new([3;32],4);
 assert_eq!(other.verify_pow_for_parent_at(&generic,nonce,diff,Some(&[9;32]),now).await,Ok(true));
 println!("same generic work admitted for parent 2 and parent 9 on independent engines");
}
#[tokio::test]
async fn a25_public_quota_result_is_ignored() {
 let dir=tempfile::tempdir().unwrap();let db=Arc::new(RedbStorage::open(&dir.path().join("q.redb")).unwrap());
 let pow=Arc::new(PowEngine::new([1;32],1));let tier=TierController::new(db,pow.clone());
 let parent=[0;32]; let now=pow.now_sec()*1000;
 let ttl=31_536_000*6000; // 1,152,000 Byte-Years > 960,000 daily baseline
 let needed=humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl);
 let available=tier.calculate_daily_quota(1.0,1.0);assert!(needed>available);
 let (challenge,diff,_)=pow.generate_challenge_for_parent(&parent);let nonce=PowEngine::solve_pow(&challenge,diff,100000).unwrap();
 let result=tier.evaluate_and_charge_with_time(None,None,Some(&challenge),Some(nonce),ttl,Some(&parent),Some(now)).await;
 println!("required={needed}; available={available}; result={result:?}");assert!(result.is_ok());
}
#[tokio::test]
async fn a25_public_node_key_registered_as_secret_is_accepted_over_http() {
 let dir=tempfile::tempdir().unwrap();let db=Arc::new(RedbStorage::open(&dir.path().join("http.redb")).unwrap());
 let (engine,_worker)=DualTierEngine::new(db.clone());let id=NodeIdentity::generate();let pow=Arc::new(PowEngine::new(*id.node_id(),8));
 let tier=Arc::new(TierController::new(db.clone(),pow.clone()));
 // Daemon does this for every configured f2f.peers element, including bare keys.
 let public_key=hex::encode(id.node_pubkey());tier.register_f2f_peer(&public_key);
 let state=AppState::new(engine,db,id.clone(),tier,pow);let now=state.net_time_ms();
 let root=make_root_request(&id,"a25-public-key-token",now);
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
 let server=tokio::spawn(async move {axum::serve(listener,build_router(state)).await.unwrap()});
 let response=reqwest::Client::new().post(format!("http://{addr}/v1/lock")).header("X-Peer-Token",&public_key).json(&root).send().await.unwrap();
 println!("NodePubKey HTTP status={}",response.status());assert_eq!(response.status(),reqwest::StatusCode::CREATED);
 server.abort();
}
#[tokio::test]
async fn a25_unauthenticated_error_is_asymmetrically_signed() {
 let dir=tempfile::tempdir().unwrap();let db=Arc::new(RedbStorage::open(&dir.path().join("reject.redb")).unwrap());
 let (engine,_worker)=DualTierEngine::new(db.clone());let id=NodeIdentity::generate();let pow=Arc::new(PowEngine::new(*id.node_id(),8));
 let tier=Arc::new(TierController::new(db.clone(),pow.clone()));let state=AppState::new(engine,db,id.clone(),tier,pow);
 let root=make_root_request(&id,"a25-unpaid-signing",state.net_time_ms());
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
 let server=tokio::spawn(async move {axum::serve(listener,build_router(state)).await.unwrap()});
 let client=reqwest::Client::new();
 for _ in 0..32 {let response=client.post(format!("http://{addr}/v1/lock")).json(&root).send().await.unwrap();assert_eq!(response.status(),reqwest::StatusCode::UNAUTHORIZED);let body:serde_json::Value=response.json().await.unwrap();println!("unpaid rejection fields={:?}",body.as_object().unwrap().keys().collect::<Vec<_>>());assert!(body.get("server_signature").is_some());}
 server.abort();
}
