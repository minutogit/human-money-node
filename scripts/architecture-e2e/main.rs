// Executed with the production App transport, Core wallet and Node HTTP/QUIC.
use std::{collections::HashMap,sync::{Arc,Mutex},time::Duration};
use human_money_core::{app_service::AppService,test_utils::{self,ACTORS},models::{profile::PublicProfile,voucher::ValueDefinition},NewVoucherData,
    wallet::{MultiTransferRequest,SourceTransfer}};
use humoco_node::{api::{routes::{public_router,build_operator_router},auth::AdminTokenManager},ingress::{PowEngine,TierController}};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    let peers=recovery::recovery_peers(21).await;
    let dir=tempfile::tempdir().unwrap();
    let password="architecture-e2e-wallet";
    let (mut sender,_)=test_utils::setup_service_with_profile(&dir.path().join("sender"),&ACTORS.alice,"Sender",password);
    let (receiver,receiver_profile)=test_utils::setup_service_with_profile(&dir.path().join("receiver"),&ACTORS.bob,"Terminal",password);
    let sender_id=sender.with_wallet(|wallet|wallet.get_user_id().to_string()).unwrap();
    let receiver_id=receiver.with_wallet(|wallet|wallet.get_user_id().to_string()).unwrap();
    let standard_path=std::path::Path::new(&std::env::var("HUMOCO_E2E_CORE_ROOT").unwrap()).join("voucher_standards/freetaler_v1/standard.toml");
    let standard=test_utils::generate_signed_standard_toml(standard_path.to_str().unwrap());
    let voucher=sender.create_new_voucher(&standard,NewVoucherData {creator_profile:PublicProfile {id:Some(sender_id),..Default::default()},
        nominal_value:ValueDefinition {amount:"100".into(),..Default::default()},..Default::default()},Some(password)).unwrap();
    let local=sender.with_wallet_and_identity(|wallet,id|wallet.list_vouchers(Some(id),None,None,None)).unwrap()[0].local_instance_id.clone();
    let standards=HashMap::from([(voucher.voucher_standard.uuid.clone(),standard)]);
    // Real L1 split, not synthetic tags/keys. Intent and outputs share the managed commit.
    let bundle=sender.create_transfer_bundle_with_l2_intents(MultiTransferRequest {recipient_id:receiver_id,sources:vec![SourceTransfer {local_instance_id:local.clone(),amount_to_send:"10".into()}],
        notes:None,sender_profile_name:None,use_privacy_mode:Some(false)},&standards,None,Some(password),0).unwrap();
    let intent=sender.pending_l2_send_intent(&local).unwrap();
    assert!(!intent.chain_request_bytes.is_empty());
    let now=peers[0].manager.net_time_ms();
    for peer in &peers {
        peer.manager.set_ge20_anchor_for_test(now-86_400_001);
        peer.readiness.mark_shard_ready(intent.shard_id);
    }
    // Established, mature, operator-authorized source readiness is a premise of
    // this checkout test. Bootstrap/recovery has separate real-daemon evidence.
    let stop=CancellationToken::new();
    let mut servers=Vec::new();
    let mut urls=Vec::new();
    let token="f2f_0123456789abcdef0123456789abcdef";
    for index in [0usize,1] {
        let peer=&peers[index];
        let pow=Arc::new(PowEngine::new(*peer.identity.node_id(),8)); pow.set_clock(peer.manager.clock().clone());
        let tier=Arc::new(TierController::new(peer.db.clone(),pow.clone())); tier.register_f2f_peer(token);
        let mut state=humoco_node::api::AppState::new(peer.engine.clone(),peer.db.clone(),peer.identity.clone(),tier,pow);
        state.peer_manager=Some(peer.manager.clone()); state.transport=Some(peer.network.clone()); state.readiness_manager=peer.readiness.clone();
        state.auth=Arc::new(AdminTokenManager::with_token("regional-read-secret",false));
        let router=if index==0 {public_router(state)} else {build_operator_router(state)};
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}",listener.local_addr().unwrap()));
        let cancel=stop.clone();
        servers.push(tokio::spawn(async move {axum::serve(listener,router).with_graceful_shutdown(async move {cancel.cancelled().await}).await.unwrap()}));
    }
    let mut settings=settings::AppSettings::default();
    settings.exclusive_custom_servers=true;
    settings.custom_servers.push(settings::CustomServerDto {url:urls[0].clone(),peer_token:Some(token.into()),..Default::default()});
    settings.regional_mesh_sources.push(settings::RegionalSourceDto {url:urls[1].clone(),public_key:peers[1].identity.public_key_hex(),bearer_token:Some("regional-read-secret".into())});
    let mut receiver=receiver;
    receiver.configure_regional_mesh_authority(checkout::configured_policy(&settings).unwrap().unwrap(),Some(password)).unwrap();
    let state=AppState {service:Mutex::new(receiver),history:Mutex::new(None),events:Mutex::new(None),contacts:Mutex::new(None),settings:Mutex::new(Some(settings.clone())),regional_views:Mutex::new(None)};
    assert!(checkout::refresh_views(&state).await.unwrap());
    let candidates=gateway_resolver::cached_candidates(&settings);
    let observations=gateway_resolver::dispatch_intents(&settings,&candidates,std::slice::from_ref(&intent)).await;
    assert!(matches!(observations[0].http_status,Some(200|201)),"actual durable chain ingress failed: {:?}",observations);
    assert_eq!(observations[0].status,"pending","HTTP success never authorizes release");
    assert!(state.service.lock().unwrap().with_wallet(|wallet|wallet.voucher_store.vouchers.is_empty()).unwrap());
    let completion=checkout::checkout_bundle(&state,"cart-architecture-1",&bundle.bundle_bytes,&standards,Some(password)).await.unwrap();
    assert!(completion.newly_committed); assert!(completion.verdict.can_release_goods_automatically);
    assert_eq!(state.service.lock().unwrap().with_wallet(|wallet|wallet.voucher_store.vouchers.len()).unwrap(),1);
    // Same cart and encrypted deed must never import value a second time.
    let retry=checkout::checkout_bundle(&state,"cart-architecture-1",&bundle.bundle_bytes,&standards,Some(password)).await.unwrap();
    assert!(!retry.newly_committed);
    assert_eq!(state.service.lock().unwrap().with_wallet(|wallet|wallet.voucher_store.vouchers.len()).unwrap(),1);
    state.service.lock().unwrap().logout();
    let mut recovered=AppService::new(&dir.path().join("receiver")).unwrap();
    recovered.login(&receiver_profile.folder_name,password,false,"test-id".into()).unwrap();
    assert_eq!(recovered.with_wallet(|wallet|wallet.voucher_store.vouchers.len()).unwrap(),1);
    assert_eq!(recovered.with_wallet(|wallet|wallet.profile.l2_checkout_purchases.len()).unwrap(),1);
    stop.cancel();
    for task in servers {tokio::time::timeout(Duration::from_secs(5),task).await.unwrap().unwrap();}
    recovery::stop_recovery_peers(peers).await;
    println!("PASS App transport -> atomic Core intent -> real HTTP ingress -> real QUIC committee -> stored recipient challenge -> atomic L1 purchase -> idempotent restart");
}
