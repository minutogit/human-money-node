---
project: human-money-node
version: "0.1.1"
phase: "active-development"
health: "green"
last_updated: "2026-09-14"
blocks: []
blocked_by: []
priority_tasks:
  - id: "NODE-001"
    title: "Core Integration (l2_gateway.rs to Node Ingress API)"
    status: "open"
    priority: "high"
    depends_on: []
    description: "Integrate human-money-core client flow with human-money-node ingress API"
  - id: "NODE-002"
    title: "Multi-Node Testnet Deployment & Stress Testing"
    status: "open"
    priority: "medium"
    depends_on: []
    description: "Deploy distributed testnet across multiple machines/containers to stress-test QUIC gossip and village merge"
---

# Human Money Node — Status

## Current Focus
- Layer-2 double-spend prevention node daemon (Chain of Authority / Collision Lock Registry).
- Multi-crate workspace: `crates/humoco-sim-core` (mathematical protocol & deterministic simulation engine) + `crates/humoco-node` (production daemon with Quinn QUIC, Axum REST, redb persistence, CLI).
- Ready for integration with `human-money-core` via `l2_gateway.rs`.

## Recent Milestones
- [x] **Phase 0**: Mathematical foundation & simulation core (70+ unit/integration tests)
- [x] **Phase 1**: Node scaffolding, CLI (`humoco init`, `keygen`, `run`), structured tracing
- [x] **Phase 2**: `redb` ACID storage engine, async RAM-to-disk flush & crash recovery
- [x] **Phase 3**: Quinn QUIC P2P transport & Dunbar gossip
- [x] **Phase 4**: Axum client ingress & PoS/Wallet lock API (< 5ms response time)
- [x] **Phase 5**: Unix domain control socket & observability
- [x] **Phase 6**: E2E cluster test suite & partition-resilience benchmarks
