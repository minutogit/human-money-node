#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../../.."
probe=crates/humoco-node/tests/audit24_probe.rs
if [[ -e "$probe" ]]; then
  echo "Refusing to overwrite existing $probe" >&2
  exit 1
fi
trap 'rm -f "$probe"' EXIT
python3 - <<'PY'
from pathlib import Path
source = Path('crates/humoco-node/tests/status_reconciliation_tests.rs').read_text()
old = 'let transport = QuicTransport::bind_with_options("127.0.0.1:0".parse().unwrap(), &id, pm.clone(), handler, cancel.clone()).unwrap();'
assert source.count(old) == 1
source = source.replace(old, 'let handler = Arc::new(AuditDelayHandler { inner: handler, index });\n        ' + old)
old = 'let tiers = Arc::new(TierController::new(storage.clone(), pow.clone()));'
assert source.count(old) == 1
source = source.replace(old, old + '\n    tiers.register_f2f_peer("audit24_token");')
extension = Path('prompts/reports/evidence/audit24-2026-10-24/probe-extension.rs').read_text()
Path('crates/humoco-node/tests/audit24_probe.rs').write_text(source + '\n' + extension)
PY
cargo test -p humoco-node --test audit24_probe audit_probe_ --offline -- --test-threads=1 --nocapture
