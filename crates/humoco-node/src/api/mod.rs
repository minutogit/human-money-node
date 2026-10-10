pub mod auth;
pub mod dashboard;
pub mod dto;
pub mod events;
pub mod health;
pub mod history;
pub mod hmc;
pub mod keys;
pub mod metrics;
pub mod qr;
pub mod routes;
pub mod system_stats;

pub use auth::AdminTokenManager;
pub use dashboard::{
    dashboard_data, render_dashboard, ConfigViewDto, DashboardData, DashboardDataDto,
    F2fClientDto, F2fFriendDto, F2fOverviewDto, PersistenceDto, RecentLockDto, RejectionsDto,
    ShardScoreSampleDto, ThermometerStatsDto, TierOverviewDto, TierSharesDto, VipAccountDto,
};
pub use events::{EventItem, EventKind, EventLog, EVENT_LOG_CAPACITY};
pub use health::{
    evaluate_health, evaluate_health_tracked, format_health_duration, HealthItem, HealthLevel,
    HealthStateTracker, HealthSummary,
};
pub use history::{HistoryPoint, HistorySampler, HISTORY_CAPACITY};

pub use dto::{
    AttestationDto, ErrorResponse, LockRecordDto,
    NodeStatusResponse, PowChallengeResponse, SyncRequest, SyncResponse,
};
pub use hmc::{
    calculate_l2_payload_hash, calculate_l2_payload_hash_raw, privacy_guard_commitment,
    verify_l2_lock_signature, wrap_and_sign_verdict, L2AuthPayload, L2ChainLockRequest,
    L2LockEntry, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};
pub use keys::{normalize_pubkey_display, parse_client_token, parse_pubkey};
pub use metrics::prometheus_metrics;
pub use routes::{build_router, AppState};
pub use system_stats::{SparklinesDto, SystemStatsCollector, SystemStatsDto};

