---
project: human-money-node
version: "0.1.1"
phase: "active-development"
health: "green"
last_updated: "2026-11-01"
blocks: []
blocked_by: []
priority_tasks:
  - id: "NODE-003"
    title: "14/20 Unoccupied Live Proofs, 1-RTT Offline-Buyer Checkout & Signed MissingLocks Anchor"
    status: "completed"
    priority: "high"
    depends_on: ["NODE-001"]
    description: "Added 14/20 `LiveSlotOccupancy::Unoccupied` quorum signing on `/v1/verify-current` (and QUIC `LiveStateRequest` fallback), combined 1-RTT `POST /v1/checkout` endpoint for offline buyers, and `anchor_lock` attachment on `L2Verdict::MissingLocks`."
  - id: "NODE-001"
    title: "Core Integration (l2_gateway.rs to Node Ingress API)"
    status: "completed"
    priority: "high"
    depends_on: []
    description: "Integrated human-money-core client flow with human-money-node ingress API: aligned `hmc.rs` domain tag to canonical `HMC_TX_AUTH_V4_DOMAIN`, exposed 5s-cached public `GET /v1/regional-mesh-view`, delegated stateless PoW evaluation directly to canonical `humoco-proto`, and permitted past `created_at_ms` timestamps for offline spends and retries."
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
- Proof-carrying ingress API aligned with Core v0.5.1 and App v0.4.0 (`NODE-001` & `NODE-003` completed): 1-RTT offline-buyer checkout, 14/20 `Unoccupied` live state proofs, signed `MissingLocks` anchor attachment, and public cached regional mesh views.
- Next: WAN testnet deployment and partition/merge stress testing (`NODE-002`).

## Recent Milestones
- [x] **Phase 0**: Mathematical foundation & simulation core (70+ unit/integration tests)
- [x] **Phase 1**: Node scaffolding, CLI (`humoco init`, `keygen`, `run`), structured tracing
- [x] **Phase 2**: `redb` ACID storage engine, async RAM-to-disk flush & crash recovery
- [x] **Phase 3**: Quinn QUIC P2P transport & Dunbar gossip
- [x] **Phase 4**: Axum client ingress & PoS/Wallet lock API (< 5ms response time)
- [x] **Phase 5**: Unix domain control socket & observability
- [x] **Phase 6**: E2E cluster test suite & partition-resilience benchmarks
- [x] **Phase 7 (`NODE-001` & `NODE-003`)**: HMC v4 domain alignment, public regional mesh view, 14/20 `Unoccupied` live proofs, 1-RTT offline-buyer checkout & signed missing-locks anchor
