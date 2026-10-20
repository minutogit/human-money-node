//! Explicit recipient-challenged current-state verification, separate from cheap status lookup.
use crate::{
    api::routes::AppState, daemon::ShardReadinessManager, identity::NodeIdentity,
    network::PeerManager, storage::DualTierEngine,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use humoco_proto::{
    live::{live_state_digest, verify_live_state_proof, LiveStateContext, LiveStateProof},
    AttestationVote,
};
use std::sync::Arc;

/// Signs only a safely ready exact local state with the currently computed frozen committee.
/// This does not establish globally common membership or source completeness.
pub async fn sign_current_state(
    engine: &DualTierEngine,
    identity: &NodeIdentity,
    pm: Option<&Arc<PeerManager>>,
    readiness: &ShardReadinessManager,
    network: humoco_sim_core::types::NetworkId,
    context: &LiveStateContext,
) -> Option<AttestationVote> {
    let digest = live_state_digest(context).ok()?;
    let expected_network = match network {
        humoco_sim_core::types::NetworkId::Mainnet => 0,
        humoco_sim_core::types::NetworkId::Testnet => 1,
    };
    if context.network != expected_network
        || !engine.is_signing_healthy()
        || !readiness.is_shard_ready(context.shard_id)
    {
        readiness.request_sync(context.shard_id);
        return None;
    }
    let pm = pm?;
    let now = pm.net_time_ms();
    if context.root_valid_until <= now || !pm.is_network_stable_ge20_for_24h(now) {
        return None;
    }
    let (committee, _, total) = pm
        .shard_committee(
            *identity.node_pubkey(),
            *identity.hrw_routing_id(),
            context.shard_id,
        )
        .await;
    let keys: Vec<_> = committee.iter().map(|m| m.node_pubkey).collect();
    if total < 20 || keys != context.committee || !keys.contains(identity.node_pubkey()) {
        return None;
    }
    // One RAM snapshot through signature calculation: never attest an uncommitted
    // insertion or combine an entry with a root from another state version.
    // No disk access or network await occurs while this read guard is held.
    let ram = engine.hmc_ram.read().await;
    let entry = ram.locks.get(&context.lookup_tag)?;
    if entry.layer2_voucher_id != context.voucher_id
        || entry.t_id != context.child_lock
        || ram.voucher_roots.get(&context.voucher_id).copied()? != context.root_valid_until
        || humoco_sim_core::types::extract_shard_id(
            ram.voucher_genesis_parents.get(&context.voucher_id)?,
        ) != context.shard_id
        || context.root_valid_until <= pm.net_time_ms()
        || ram.durable_entries.get(&context.lookup_tag)
            != Some(&(context.state_digest, context.root_valid_until))
        || !engine.is_signing_healthy()
        || !readiness.is_shard_ready(context.shard_id)
    {
        return None;
    }
    let state = serde_json::to_vec(entry).ok()?;
    if *blake3::hash(&state).as_bytes() != context.state_digest {
        return None;
    }
    Some(AttestationVote {
        signer_pubkey: *identity.node_pubkey(),
        signature: identity.signing_key().sign(&digest).to_bytes(),
    })
}

/// Collects a FINAL live proof; supplied roster is checked locally and must be independently justified by the recipient.
pub async fn verify_current(
    State(state): State<AppState>,
    Json(context): Json<LiveStateContext>,
) -> Response {
    let Ok(digest) = live_state_digest(&context) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(pm) = state.peer_manager.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let client_bucket = u16::from_le_bytes([context.parent_lock[0], context.parent_lock[1]]);
    let day = state
        .tier_controller
        .current_epoch_day_at(state.net_time_ms());
    if state
        .tier_controller
        .evaluate_read_quota(client_bucket, 20, day, 1.0)
        .is_err()
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let (committee, remotes, total) = pm
        .shard_committee(
            *state.identity.node_pubkey(),
            *state.identity.hrw_routing_id(),
            context.shard_id,
        )
        .await;
    if total < 20
        || committee.iter().map(|m| m.node_pubkey).collect::<Vec<_>>() != context.committee
    {
        return StatusCode::CONFLICT.into_response();
    }
    let mut proof = LiveStateProof {
        context: context.clone(),
        votes: Vec::new(),
    };
    if let Some(vote) = sign_current_state(
        &state.engine,
        &state.identity,
        state.peer_manager.as_ref(),
        &state.readiness_manager,
        state.network_id,
        &context,
    )
    .await
    {
        proof.votes.push(vote);
    }
    let Some(transport) = state.transport.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(payload) = serde_json::to_vec(&context) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut jobs = tokio::task::JoinSet::new();
    for (member, addr) in remotes {
        let transport = transport.clone();
        let payload = payload.clone();
        jobs.spawn(async move {
            let conn = transport.connect_peer(addr).await.ok()?;
            let actual = crate::network::tls::extract_peer_identity_from_connection(&conn)?.0;
            if actual != member.node_pubkey {
                return None;
            }
            let header = humoco_sim_core::wire::WireHeader::new(
                humoco_sim_core::wire::MsgType::LiveStateRequest as u16,
                1,
                0,
                0,
                payload.len() as u32,
            );
            let (h, bytes) = transport
                .send_request(&conn, &header, &payload)
                .await
                .ok()?;
            if h.msg_type != humoco_sim_core::wire::MsgType::LiveStateResponse as u16
                || h.flags != 0
            {
                return None;
            }
            let vote: AttestationVote = bincode::deserialize(&bytes).ok()?;
            if vote.signer_pubkey != member.node_pubkey {
                return None;
            }
            let key = VerifyingKey::from_bytes(&vote.signer_pubkey).ok()?;
            key.verify_strict(&digest, &Signature::from_bytes(&vote.signature))
                .ok()?;
            Some(vote)
        });
    }
    let _ = tokio::time::timeout(std::time::Duration::from_millis(800), async {
        while proof.votes.len() < 14 && proof.votes.len() + jobs.len() >= 14 {
            let Some(result) = jobs.join_next().await else {
                break;
            };
            if let Ok(Some(vote)) = result {
                if !proof
                    .votes
                    .iter()
                    .any(|v| v.signer_pubkey == vote.signer_pubkey)
                {
                    proof.votes.push(vote);
                }
            }
        }
    })
    .await;
    jobs.abort_all();
    if verify_live_state_proof(&proof, &context).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (StatusCode::OK, Json(proof)).into_response()
}
