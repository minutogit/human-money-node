//! Private loopback-only operator HTTP listener, separate from public ingress.
use crate::{api::routes::AppState, error::NodeError};
use std::net::SocketAddr;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Binds private diagnostics only when explicitly configured; never falls back publicly.
pub async fn spawn_operator_listener(
    state: AppState,
    addr: Option<SocketAddr>,
    cancel: CancellationToken,
) -> Result<Option<JoinHandle<Result<(), NodeError>>>, NodeError> {
    let Some(addr) = addr else {
        return Ok(None);
    };
    if !addr.ip().is_loopback() {
        return Err(NodeError::Daemon(
            "operator listener must bind loopback".into(),
        ));
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(address = %listener.local_addr()?, "Private operator HTTP listener bound");
    let app = crate::api::routes::build_operator_router(state);
    let token = cancel;
    Ok(Some(tokio::spawn(async move {
        let shutdown = token.clone();
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            })
            .await
        {
            tracing::error!(%error, "Private operator listener failed");
            token.cancel();
            return Err(NodeError::Io(error));
        }
        Ok(())
    })))
}
