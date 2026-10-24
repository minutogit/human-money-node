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
probe=r'''    // Independent audit probes; product sources remain untouched.
    let probe_now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
    let (_, probe_views) = checkout::cached_views(&state).unwrap();
    {
        let mut service = state.service.lock().unwrap();
        let expired_view = service.begin_checkout_purchase("audit-stale-view", &bundle.bundle_bytes, &probe_views, probe_now+61_000, Some(password));
        assert!(expired_view.is_err(), "cached 60-second views must reject after 61 seconds");
        println!("AUDIT: cached regional views reject at +61s: {:?}", expired_view.err());
        let mut accepted = 0;
        for i in 0..256 {
            let id = format!("audit-abandoned-{i}");
            match service.begin_checkout_purchase(&id, &bundle.bundle_bytes, &probe_views, probe_now, Some(password)) {
                Ok(_) => accepted += 1,
                Err(error) => { println!("AUDIT: purchase table rejects after {accepted} new reservations: {error}"); break; }
            }
        }
        assert_eq!(accepted,255,"existing completed purchase plus 255 reservations fills the permanent 256 limit");
        let retry = service.begin_checkout_purchase("audit-abandoned-0", &bundle.bundle_bytes, &probe_views, probe_now+31_000, Some(password)).unwrap();
        let expiry = service.with_wallet(|w|w.profile.l2_checkout_purchases["audit-abandoned-0"].expires_at_ms).unwrap();
        assert!(expiry <= probe_now+31_000);
        assert_ne!(retry.recipient_nonce,[0;32]);
        println!("AUDIT: same expired purchase returns its expired challenge; no renewal; table stays full");
    }
'''
main=main.replace('    state.service.lock().unwrap().logout();',probe+'    state.service.lock().unwrap().logout();')
main=main.replace('assert_eq!(recovered.with_wallet(|wallet|wallet.profile.l2_checkout_purchases.len()).unwrap(),1);','assert_eq!(recovered.with_wallet(|wallet|wallet.profile.l2_checkout_purchases.len()).unwrap(),256);')
(out/'src/main.rs').write_text(head+main)
PY
export HUMOCO_E2E_CORE_ROOT="$core_root"
export CARGO_TARGET_DIR="${HUMOCO_E2E_TARGET_DIR:-$node_root/target/architecture-e2e}"
cargo run --offline --manifest-path "$stage_dir/Cargo.toml"
