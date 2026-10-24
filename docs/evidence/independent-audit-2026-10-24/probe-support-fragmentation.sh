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
(out/'src/main.rs').write_text(head+'\nuse humoco_sim_core::types::{LockRecord,SimTime};\n#[tokio::main]\nasync fn main(){\n let peers=recovery::recovery_peers(20).await;\n let now=peers[0].manager.net_time_ms();\n let shard=42u16; let mut parent=[7;32]; parent[..2].copy_from_slice(&shard.to_be_bytes());\n let row=LockRecord::new(parent,[8;32],vec![9],SimTime(now),SimTime(now+600_000));\n for peer in &peers {\n  peer.manager.set_ge20_anchor_for_test(now-86_400_001);\n  peer.db.put_lock(&row,now+600_000).unwrap();\n  peer.engine.recover_from_disk(SimTime(now)).await.unwrap();\n  peer.readiness.mark_shard_ready(shard);\n }\n for i in 0..7 {\n  let target=&peers[i];\n  let result=humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,&target.identity,&target.readiness,&target.cancel).await.unwrap();\n  println!("AUDIT: same objective cut, sequential recipient {} => ready {}",i+1,result);\n  if i<6 {assert!(result);assert_eq!(target.db.native_confirmation_support(&parent).unwrap().unwrap().class,2);} else {assert!(!result);assert!(!target.readiness.is_shard_ready(shard));}\n  tokio::time::sleep(std::time::Duration::from_millis(2100)).await;\n }\n println!("AUDIT CONFIRMED: six admitted support upgrades split otherwise identical objective state; seventh target cannot obtain 14 identical support commitments");\n recovery::stop_recovery_peers(peers).await;\n}\n')
PY
export HUMOCO_E2E_CORE_ROOT="$core_root"
export CARGO_TARGET_DIR="${HUMOCO_E2E_TARGET_DIR:-$node_root/target/architecture-e2e}"
cargo run --offline --manifest-path "$stage_dir/Cargo.toml"
