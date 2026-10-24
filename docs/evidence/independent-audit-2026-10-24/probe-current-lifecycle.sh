#!/usr/bin/env bash
# Reproduce the actual local App/Core/Node dependency graph without altering a
# release manifest or introducing a production Node dependency into the wallet.
set -euo pipefail
node_root="/home/basti/Coding/humoco/human-money-node"
core_root="${HUMOCO_CORE_ROOT:-$(dirname "$node_root")/human-money-core}"
app_root="${HUMOCO_APP_ROOT:-$(dirname "$node_root")/human-money-app}"
stage_dir="$(mktemp -d /tmp/humoco-architecture-e2e.XXXXXX)"
trap 'rm -rf "$stage_dir"' EXIT
python3 - "$node_root" "$core_root" "$app_root" "$stage_dir" <<'PY'
import sys,json,pathlib
node,core,app,out=map(pathlib.Path,sys.argv[1:])
q=lambda p:json.dumps(str(p))
(out/'src').mkdir()
(out/'Cargo.toml').write_text('''[package]
name="humoco-architecture-e2e"
version="0.0.0"
edition="2021"
[dependencies]
humoco-node={path='''+q(node/'crates/humoco-node')+'''}
humoco-sim-core={path='''+q(node/'crates/humoco-sim-core')+'''}
human_money_core={path='''+q(core)+''',features=["test-utils"]}
tokio={version="1",features=["rt-multi-thread","macros","net","time","io-util"]}
tokio-util={version="0.7",features=["rt"]}
serde={version="1",features=["derive"]}
serde_json="1"
reqwest={version="0.13.2",features=["json"]}
axum="0.7"
blake3="1.5"
bincode="1.3"
ed25519-dalek="2.1"
chrono="0.4"
log="0.4"
uuid={version="1",features=["v4","serde"]}
tempfile="3"
[profile.dev]
debug=1
''')
modules={'settings':app/'src-tauri/src/settings.rs','models':app/'src-tauri/src/models/mod.rs','state':app/'src-tauri/src/state.rs','gateway_resolver':app/'src-tauri/src/gateway_resolver.rs','checkout':app/'src-tauri/src/checkout.rs','recovery':node/'crates/humoco-node/tests/common/recovery.rs'}
head='\n'.join('#[path='+q(path)+'] mod '+name+';' for name,path in modules.items())+'\nuse state::AppState;\n'
main=(node/'scripts/architecture-e2e/main.rs').read_text()
probe='    // Independent audit: exercise current production Core and App modules.\n    use human_money_core::humoco_proto::{mesh::regional_committee,live::{LiveStateProof,live_state_digest}};\n    use ed25519_dalek::Signer;\n    let probe_now=u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();\n    let (_,old_views)=checkout::cached_views(&state).unwrap();\n    let old_context={\n        let mut service=state.service.lock().unwrap();\n        service.begin_checkout_purchase("audit-turnover",&bundle.bundle_bytes,&old_views,probe_now,Some(password)).unwrap()\n    };\n    let policy=checkout::configured_policy(&settings).unwrap().unwrap();\n    let mut new_views=old_views.clone();\n    let view=&mut new_views[0];\n    view.members[0].hrw_routing_id=[207;32];\n    view.signature=peers[1].identity.signing_key().sign(&view.digest().unwrap()).to_bytes();\n    let new_roster=regional_committee(&policy,&new_views,intent.shard_id,probe_now+31_000).unwrap();\n    assert_ne!(old_context.committee,new_roster);\n    let renewed={\n        let mut service=state.service.lock().unwrap();\n        service.begin_checkout_purchase("audit-turnover",&bundle.bundle_bytes,&new_views,probe_now+31_000,Some(password)).unwrap()\n    };\n    assert_ne!(renewed.recipient_nonce,old_context.recipient_nonce);\n    assert_eq!(renewed.committee,old_context.committee);\n    let mut proof=LiveStateProof {context:renewed.clone(),votes:Vec::new()};\n    proof.context.committee=new_roster;\n    let digest=live_state_digest(&proof.context).unwrap();\n    for key in proof.context.committee.iter().take(14) {\n        let peer=peers.iter().find(|p|p.identity.node_pubkey()==key).unwrap();\n        proof.votes.push(human_money_core::humoco_proto::AttestationVote {signer_pubkey:*key,signature:peer.identity.signing_key().sign(&digest).to_bytes()});\n    }\n    let err=state.service.lock().unwrap().complete_checkout_purchase("audit-turnover",&bundle.bundle_bytes,&proof,&new_views,&standards,probe_now+31_000,Some(password)).unwrap_err();\n    assert!(err.to_string().contains("purchase authority changed"));\n    println!("AUDIT CONFIRMED: expired reservation renews nonce but retains obsolete committee; authenticated current proof rejected: {err}");\n    let mut wrong=old_context.clone();\n    wrong.child_lock=[123;32]; wrong.state_digest=[234;32];\n    let conflict=gateway_resolver::fetch_live_proof(&candidates,&wrong).await.unwrap();\n    assert!(conflict.is_none());\n    let actual=gateway_resolver::fetch_live_proof(&candidates,&old_context).await.unwrap();\n    assert!(actual.is_some());\n    println!("AUDIT CONFIRMED: real HTTP/QUIC lookup returns proof only for exact requested child; no canonical conflicting-child discovery");\n    let policy=checkout::configured_policy(&settings).unwrap().unwrap();\n    sender.configure_regional_mesh_authority(policy,Some(password)).unwrap();\n    let reconciliation=sender.begin_intent_reconciliation(&local,&old_views,probe_now+31_000,Some(password)).unwrap();\n    let mut proof=LiveStateProof {context:reconciliation.clone(),votes:Vec::new()};\n    let digest=live_state_digest(&reconciliation).unwrap();\n    for key in reconciliation.committee.iter().take(14) {\n        let peer=peers.iter().find(|p|p.identity.node_pubkey()==key).unwrap();\n        proof.votes.push(human_money_core::humoco_proto::AttestationVote {signer_pubkey:*key,signature:peer.identity.signing_key().sign(&digest).to_bytes()});\n    }\n    sender.complete_intent_reconciliation(&local,&proof,&old_views,probe_now+31_000,Some(password)).unwrap();\n    assert!(sender.unresolved_l2_send_intents().unwrap().is_empty());\n    assert!(sender.pending_l2_send_intent(&local).unwrap().terminal_resolution.is_some());\n    println!("AUDIT CONFIRMED: terminal-only journal is invisible to host unresolved-intent enumeration; supervisor returns before future cleanup");\n    assert_eq!(sender.cleanup_terminal_intents(60_000,probe_now+92_000,Some(password)).unwrap(),1);\n    let delayed=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();\n    let delayed_url=format!("http://{}",delayed.local_addr().unwrap());\n    let delayed_view=serde_json::to_vec(&old_views[0]).unwrap();\n    let delay_task=tokio::spawn(async move {\n        use tokio::io::{AsyncReadExt,AsyncWriteExt};\n        let (mut stream,_)=delayed.accept().await.unwrap();\n        let mut buf=[0;4096]; let _=stream.read(&mut buf).await.unwrap();\n        tokio::time::sleep(Duration::from_millis(1100)).await;\n        stream.write_all(format!("HTTP/1.1 200 OK\\r\\nContent-Length: {}\\r\\nConnection: close\\r\\n\\r\\n",delayed_view.len()).as_bytes()).await.unwrap();\n        stream.write_all(&delayed_view).await.unwrap();\n    });\n    state.settings.lock().unwrap().as_mut().unwrap().regional_mesh_sources[0].url=delayed_url;\n    *state.regional_views.lock().unwrap()=None;\n    let started=std::time::Instant::now();\n    let result=checkout::checkout_bundle(&state,"audit-cold-cache",&bundle.bundle_bytes,&standards,Some(password)).await;\n    let elapsed=started.elapsed();\n    assert!(elapsed>=Duration::from_millis(1100));\n    delay_task.await.unwrap();\n    println!("AUDIT CONFIRMED: cold cache checkout waits for regional HTTP source on payment path: {:?}; result {:?}",elapsed,result.err().map(|e|e.message));\n\n'
main=main.replace('    state.service.lock().unwrap().logout();',probe+'    state.service.lock().unwrap().logout();')
main=main.replace('l2_checkout_purchases.len()).unwrap(),1);','l2_checkout_purchases.len()).unwrap(),3);')
(out/'src/main.rs').write_text(head+main)
PY
export HUMOCO_E2E_CORE_ROOT="$core_root"
export CARGO_TARGET_DIR="${HUMOCO_E2E_TARGET_DIR:-$node_root/target/architecture-e2e}"
cargo run --offline --manifest-path "$stage_dir/Cargo.toml"
