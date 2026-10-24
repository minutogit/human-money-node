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

fixture=(node/'crates/humoco-node/tests/common/recovery.rs').read_text()
fixture=fixture.replace('inner: handler, db: db.clone(), corrupt, support_fault: peer_fault, identity:identity.clone(), pages:', 'inner: handler, db: db.clone(), audit_bad: peer_index == 0, corrupt, support_fault: peer_fault, identity:identity.clone(), pages:')
fixture=fixture.replace('struct CorruptSnapshot {','struct CorruptSnapshot {\n    audit_bad: bool,')
fixture=fixture.replace('let reply = self.inner.handle_authenticated(header,payload,owner);', '''let db=self.db.clone(); let audit_bad=self.audit_bad;
        let reply = self.inner.handle_authenticated(header,payload,owner);''')
fixture=fixture.replace('if freeze && support_fault > 0', '''if freeze && header.flags == 0 {
                if audit_bad {
                    use ed25519_dalek::Signer;
                    let (row,root)=db.get_lock(&[21;32]).unwrap().unwrap();
                    let key=format!("native:{}", row.parent_lock.iter().map(|b|format!("{b:02x}")).collect::<String>());
                    let mut hash=blake3::Hasher::new();
                    let domain=b"HUMOCO_V1_INHERITED_SUPPORT_STATE";
                    hash.update(&[domain.len() as u8]); hash.update(domain); hash.update(&[1]); hash.update(&shard.to_le_bytes());
                    hash.update(&[0]); hash.update(&(key.len() as u16).to_le_bytes()); hash.update(key.as_bytes());
                    hash.update(&row.parent_lock); hash.update(&row.id); hash.update(&[0;32]); hash.update(&root.to_le_bytes()); hash.update(&[2]);
                    let mut reply:humoco_node::network::framing::FrozenShardReply=bincode::deserialize(&bytes).unwrap();
                    reply.support_digest=*hash.finalize().as_bytes();
                    reply.signature=identity.signing_key().sign(&reply.signing_digest(humoco_sim_core::types::NetworkId::Mainnet,shard,identity.node_pubkey(),&owner.unwrap())).to_bytes().to_vec();
                    bytes=bincode::serialize(&reply).unwrap(); header.payload_len=bytes.len() as u32;
                } else { tokio::time::sleep(std::time::Duration::from_millis(250)).await; }
            }
            if active && audit_bad {
                let mut page=humoco_node::network::framing::ActiveSyncResponse::from_bytes(&bytes).unwrap();
                for (row,root) in &page.payload.locks {
                    let key=format!("native:{}",row.parent_lock.iter().map(|b|format!("{b:02x}")).collect::<String>());
                    page.payload.support.push((0,key,humoco_node::storage::db::support::ConfirmationSupport {parent:row.parent_lock,child:row.id,class:2,root_valid_until_ms:*root,verified_context:[77;32]}));
                }
                bytes=page.to_bytes().unwrap(); header.payload_len=bytes.len() as u32;
            }
            if freeze && support_fault > 0''')
(out/'src/recovery.rs').write_text(fixture)
head=head.replace(q(node/'crates/humoco-node/tests/common/recovery.rs'),q(out/'src/recovery.rs'))

(out/'src/main.rs').write_text(head+'\nuse humoco_sim_core::types::{LockRecord,SimTime};\n#[tokio::main]\nasync fn main(){\n let peers=recovery::recovery_peers(4).await;\n let now=peers[0].manager.net_time_ms();\n let row=LockRecord::new([21;32],[22;32],vec![23],SimTime(now),SimTime(now+600_000));\n let shard=u16::from_be_bytes([21;2]);\n for peer in &peers[..3] {\n  peer.db.put_lock(&row,now+600_000).unwrap(); peer.engine.recover_from_disk(SimTime(now)).await.unwrap(); peer.readiness.mark_shard_ready(shard);\n  assert!(peer.db.native_confirmation_support(&row.parent_lock).unwrap().is_none());\n }\n let target=&peers[3];\n let result=humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,&target.identity,&target.readiness,&target.cancel).await.unwrap();\n assert!(result);\n let class=target.db.native_confirmation_support(&row.parent_lock).unwrap().unwrap().class;\n println!("AUDIT observed: one Byzantine source, two honest unknown sources, N=4/Q=3, installed class={class}, ready={}",target.readiness.is_shard_ready(shard));\n assert_eq!(class,2,"defect oracle: one authenticated source\'s fabricated inherited FINAL is accepted");\n recovery::stop_recovery_peers(peers).await;\n}\n')
PY
export HUMOCO_E2E_CORE_ROOT="$core_root"
export CARGO_TARGET_DIR="${HUMOCO_E2E_TARGET_DIR:-$node_root/target/architecture-e2e}"
cargo run --offline --manifest-path "$stage_dir/Cargo.toml"
