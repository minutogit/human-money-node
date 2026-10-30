#!/usr/bin/env bash
# Synchronizes or checks byte-for-byte parity between the sibling ../humoco-proto
# repository (when present in local multi-repo checkouts) and crates/humoco-proto.
set -euo pipefail

node_root="$(cd "$(dirname "$0")/.." && pwd)"
sibling_proto="${HUMOCO_PROTO_ROOT:-$(dirname "$node_root")/humoco-proto}"
local_proto="$node_root/crates/humoco-proto"

mode="${1:---check}"

if [[ ! -d "$sibling_proto/src" ]]; then
    echo "Sibling humoco-proto not found at $sibling_proto; using standalone crates/humoco-proto."
    exit 0
fi

case "$mode" in
    --pull)
        mkdir -p "$local_proto/src"
        cp "$sibling_proto/Cargo.toml" "$local_proto/Cargo.toml"
        rm -f "$local_proto/src/"*.rs
        cp "$sibling_proto/src/"*.rs "$local_proto/src/"
        echo "Synced $sibling_proto -> $local_proto"
        ;;
    --check)
        diff -u "$sibling_proto/Cargo.toml" "$local_proto/Cargo.toml"
        diff -ru "$sibling_proto/src" "$local_proto/src"
        echo "OK: crates/humoco-proto matches $sibling_proto byte-for-byte."
        ;;
    *)
        echo "Usage: $0 [--check | --pull]" >&2
        exit 2
        ;;
esac
