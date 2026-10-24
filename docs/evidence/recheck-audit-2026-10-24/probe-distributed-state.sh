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
(out/'src/main.rs').write_text(head+'\nuse humoco_sim_core::types::{LockRecord,SimTime};\n#[tokio::main]\nasync fn main(){\n let peers=recovery::recovery_peers(20).await;\n let now=peers[0].manager.net_time_ms(); let shard=42u16;\n let mut p=[7;32];p[..2].copy_from_slice(&shard.to_be_bytes());\n let mut q=[8;32];q[..2].copy_from_slice(&shard.to_be_bytes());\n let a=LockRecord::new(p,[8;32],vec![1],SimTime(now),SimTime(now+600_000));\n let b=LockRecord::new(q,[9;32],vec![2],SimTime(now),SimTime(now+600_000));\n for (i,peer) in peers.iter().enumerate(){\n  peer.manager.set_ge20_anchor_for_test(now-86_400_001);\n  if i<14 {peer.db.put_lock(&a,now+600_000).unwrap();}\n  if i<8 || i>=14 {peer.db.put_lock(&b,now+600_000).unwrap();}\n  peer.engine.recover_from_disk(SimTime(now)).await.unwrap();peer.readiness.mark_shard_ready(shard);\n }\n // AB:8, A:6, B:6. Each exclusion has fourteen actual qualified holders.\n let target=&peers[0];\n let result=humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,&target.identity,&target.readiness,&target.cancel).await.unwrap();\n assert!(result);assert!(target.readiness.is_shard_ready(shard));\n assert!(target.db.get_lock(&p).unwrap().is_some());assert!(target.db.get_lock(&q).unwrap().is_some());\n println!("F02 VERIFIED: authentic AB8/A6/B6 compatible state reconciles per-fact distributed witnesses and reaches READY");\n recovery::stop_recovery_peers(peers).await;\n}\n')
PY
export HUMOCO_E2E_CORE_ROOT="$core_root"
export CARGO_TARGET_DIR="${HUMOCO_E2E_TARGET_DIR:-$node_root/target/architecture-e2e}"
cargo run --offline --manifest-path "$stage_dir/Cargo.toml"
