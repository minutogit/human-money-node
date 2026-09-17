pub mod dashboard;
pub mod dto;
pub mod hmc;
pub mod metrics;
pub mod qr;
pub mod routes;

pub use dashboard::{dashboard_data, render_dashboard, DashboardData};

pub use dto::{
    AttestationDto, ErrorResponse, LockRecordDto, LockSubmitRequest, LockSubmitResponse,
    NodeStatusResponse, PowChallengeResponse, SyncRequest, SyncResponse,
};
pub use hmc::{
    calculate_l2_payload_hash, calculate_l2_payload_hash_raw, privacy_guard_commitment,
    verify_l2_lock_signature, wrap_and_sign_verdict, L2AuthPayload, L2ChainLockRequest,
    L2LockEntry, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};
pub use metrics::prometheus_metrics;
pub use routes::{build_router, AppState};
