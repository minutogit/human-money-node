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
    live::{
        live_state_digest, live_unoccupied_digest, verify_live_state_proof,
        verify_live_unoccupied_proof, LiveSlotOccupancy, LiveStateContext, LiveStateProof,
    },
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
    let is_unoccupied = context.child_lock == [0; 32];
    if is_unoccupied && (context.state_digest != [0; 32] || context.root_valid_until != 0) {
        return None;
    }
    let digest = if is_unoccupied {
        live_unoccupied_digest(context).ok()?
    } else {
        live_state_digest(context).ok()?
    };
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
    if (!is_unoccupied && context.root_valid_until <= now) || !pm.is_network_stable_ge20_for_24h(now) {
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
    if is_unoccupied {
        if ram.locks.contains_key(&context.lookup_tag)
            || !engine.is_signing_healthy()
            || !readiness.is_shard_ready(context.shard_id)
        {
            return None;
        }
    } else {
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
    }
    Some(AttestationVote {
        signer_pubkey: *identity.node_pubkey(),
        signature: identity.signing_key().sign(&digest).to_bytes(),
    })
}

#[derive(Clone, Copy, Debug)]
pub struct LiveDeadline(pub tokio::time::Instant);

/// Named server-side processing budget for live proof collection.
/// Leaves nominal headroom beneath the client's absolute 800 ms checkout deadline.
pub const LIVE_PROOF_SERVER_BUDGET: std::time::Duration = std::time::Duration::from_millis(750);

/// Bounded independent live-verification pipeline for one remote committee member.
/// Executes at most 3 RPCs on an owned connection:
struct MemberLiveQuery {
    transport: crate::network::QuicTransport,
    member_pubkey: [u8; 32],
    addr: std::net::SocketAddr,
    requested_context: LiveStateContext,
    deadline: tokio::time::Instant,
    state_identity: NodeIdentity,
    net_time_ms: u64,
    declared_write_ema: u64,
    declared_read_ema: u64,
    network_id: humoco_sim_core::types::NetworkId,
}

/// Pipeline for an individual committee member over an owned QUIC connection:
/// 1. Ask for signature on requested context (fast path).
/// 2. If claim mismatched (NOT_READY), query current status of that member.
/// 3. If valid candidate discovered, ask that member to sign the discovered context.
async fn query_member_live_vote(
    query: MemberLiveQuery,
) -> Option<(LiveStateContext, AttestationVote)> {
    if tokio::time::Instant::now() >= query.deadline {
        return None;
    }
    let conn = query.transport.connect_peer(query.addr).await.ok()?;
    let actual = crate::network::tls::extract_peer_identity_from_connection(&conn)?.0;
    if actual != query.member_pubkey {
        return None;
    }

    // RPC 1: Initial claim request (fast path)
    let payload = serde_json::to_vec(&query.requested_context).ok()?;
    let header = humoco_sim_core::wire::WireHeader::new(
        humoco_sim_core::wire::MsgType::LiveStateRequest as u16,
        1,
        0,
        0,
        payload.len() as u32,
    );
    let (h, bytes) = query
        .transport
        .send_request(&conn, &header, &payload)
        .await
        .ok()?;
    if h.msg_type == humoco_sim_core::wire::MsgType::LiveStateResponse as u16
        && h.flags == 0
        && !bytes.is_empty()
    {
        let vote: AttestationVote = bincode::deserialize(&bytes).ok()?;
        if vote.signer_pubkey == query.member_pubkey {
            let digest_res = if query.requested_context.child_lock == [0; 32] {
                humoco_proto::live::live_unoccupied_digest(&query.requested_context)
            } else {
                live_state_digest(&query.requested_context)
            };
            if let Ok(digest) = digest_res {
                let key = VerifyingKey::from_bytes(&vote.signer_pubkey).ok()?;
                if key
                    .verify_strict(&digest, &Signature::from_bytes(&vote.signature))
                    .is_ok()
                {
                    return Some((query.requested_context, vote));
                }
            }
        }
    }

    // Do not retry unauthorized, suspended, or quota-exceeded outcomes
    if (h.flags
        & (humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED
            | humoco_sim_core::wire::FLAG_PEER_SUSPENDED
            | humoco_sim_core::wire::FLAG_UNAUTHORIZED))
        != 0
    {
        return None;
    }

    // RPC 2: Fallback candidate discovery on claim mismatch (represented by NOT_READY)
    if tokio::time::Instant::now() >= query.deadline {
        return None;
    }
    let sender_pubkey = *query.state_identity.node_pubkey();
    let env_digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        0,
        0,
        query.net_time_ms,
        query.declared_write_ema,
        query.declared_read_ema,
        0,
        true,
        &[0u8; 32],
    );
    let sender_signature = query
        .state_identity
        .signing_key()
        .sign(&env_digest)
        .to_bytes();
    let status_query = crate::network::framing::StatusQueryPayload {
        lock_id: [0u8; 32],
        parent_lock: query.requested_context.parent_lock,
        shard_id: query.requested_context.shard_id,
        sender_pubkey,
        declared_write_ema_micro_bj: query.declared_write_ema,
        current_read_ema_credits: query.declared_read_ema,
        timestamp_ms: query.net_time_ms,
        sender_signature,
    };
    let status_payload = bincode::serialize(&status_query).ok()?;
    let status_header = humoco_sim_core::wire::WireHeader::new(
        humoco_sim_core::wire::MsgType::StatusQuery as u16,
        2,
        0,
        crate::network::framing::FLAG_AUTHENTICATED_DISCOVERY,
        status_payload.len() as u32,
    );
    let (status_resp_h, status_resp_bytes) = query
        .transport
        .send_request(&conn, &status_header, &status_payload)
        .await
        .ok()?;
    if status_resp_h.msg_type != humoco_sim_core::wire::MsgType::StatusResponse as u16
        || (status_resp_h.flags
            & (humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED
                | humoco_sim_core::wire::FLAG_PEER_SUSPENDED
                | humoco_sim_core::wire::FLAG_UNAUTHORIZED
                | humoco_sim_core::wire::FLAG_NOT_READY))
            != 0
    {
        return None;
    }

    // Case A: The ready remote custodian reports NO lock at parent_lock!
    if status_resp_bytes.is_empty() {
        let mut unoccupied_ctx = query.requested_context.clone();
        unoccupied_ctx.child_lock = [0; 32];
        unoccupied_ctx.state_digest = [0; 32];
        unoccupied_ctx.root_valid_until = 0;

        if tokio::time::Instant::now() >= query.deadline {
            return None;
        }
        let cand_payload = serde_json::to_vec(&unoccupied_ctx).ok()?;
        let cand_header = humoco_sim_core::wire::WireHeader::new(
            humoco_sim_core::wire::MsgType::LiveStateRequest as u16,
            3,
            0,
            0,
            cand_payload.len() as u32,
        );
        let (cand_h, cand_bytes) = query
            .transport
            .send_request(&conn, &cand_header, &cand_payload)
            .await
            .ok()?;
        if cand_h.msg_type == humoco_sim_core::wire::MsgType::LiveStateResponse as u16
            && cand_h.flags == 0
            && !cand_bytes.is_empty()
        {
            let vote: AttestationVote = bincode::deserialize(&cand_bytes).ok()?;
            if vote.signer_pubkey == query.member_pubkey {
                let digest = humoco_proto::live::live_unoccupied_digest(&unoccupied_ctx).ok()?;
                let key = VerifyingKey::from_bytes(&vote.signer_pubkey).ok()?;
                if key
                    .verify_strict(&digest, &Signature::from_bytes(&vote.signature))
                    .is_ok()
                {
                    return Some((unoccupied_ctx, vote));
                }
            }
        }
        return None;
    }

    // Case B: Existing rival lock discovery!
    if status_resp_bytes.len() > crate::network::framing::MAX_AUTHENTICATED_DISCOVERY_BYTES
        || (status_resp_h.flags & crate::network::framing::FLAG_AUTHENTICATED_DISCOVERY) == 0
    {
        return None;
    }
    let discovery: crate::network::framing::AuthenticatedSlotDiscovery =
        serde_json::from_slice(&status_resp_bytes).ok()?;
    if discovery.custodian_pubkey != query.member_pubkey
        || discovery.entry.layer2_voucher_id != query.requested_context.voucher_id
        || !crate::api::hmc::verify_l2_lock_entry_signature(
            &discovery.entry,
            &query.requested_context.lookup_tag,
        )
    {
        return None;
    }
    let state_bytes = serde_json::to_vec(&discovery.entry).ok()?;
    let state_digest = *blake3::hash(&state_bytes).as_bytes();
    if discovery.root_valid_until <= query.net_time_ms {
        return None;
    }
    if let Some(ref del) = discovery.entry.deletable_at {
        let del_ms = crate::storage::db::roots::parse_deletable_at_ms(del).ok()?;
        if crate::storage::db::roots::is_root(&query.requested_context.lookup_tag, &discovery.entry) {
            if del_ms != discovery.root_valid_until {
                return None;
            }
        } else if del_ms > discovery.root_valid_until || del_ms <= query.net_time_ms {
            return None;
        }
    }
    if let Some(ref proof) = discovery.entry.causal_output {
        if proof.root_valid_until_ms != discovery.root_valid_until {
            return None;
        }
    }
    let expected_network = match query.network_id {
        humoco_sim_core::types::NetworkId::Mainnet => 0,
        humoco_sim_core::types::NetworkId::Testnet => 1,
    };
    if !discovery.verify_signature(
        expected_network,
        query.requested_context.shard_id,
        2,
        &query.requested_context.parent_lock,
        &state_digest,
    ) {
        return None;
    }

    let mut candidate_context = query.requested_context.clone();
    candidate_context.child_lock = discovery.entry.t_id;
    candidate_context.state_digest = state_digest;
    candidate_context.root_valid_until = discovery.root_valid_until;

    // RPC 3: Request signature on discovered candidate from this same member
    if tokio::time::Instant::now() >= query.deadline {
        return None;
    }
    let candidate_payload = serde_json::to_vec(&candidate_context).ok()?;
    let candidate_header = humoco_sim_core::wire::WireHeader::new(
        humoco_sim_core::wire::MsgType::LiveStateRequest as u16,
        3,
        0,
        0,
        candidate_payload.len() as u32,
    );
    let (cand_h, cand_bytes) = query
        .transport
        .send_request(&conn, &candidate_header, &candidate_payload)
        .await
        .ok()?;
    if cand_h.msg_type == humoco_sim_core::wire::MsgType::LiveStateResponse as u16
        && cand_h.flags == 0
        && !cand_bytes.is_empty()
    {
        let vote: AttestationVote = bincode::deserialize(&cand_bytes).ok()?;
        if vote.signer_pubkey == query.member_pubkey {
            let digest = live_state_digest(&candidate_context).ok()?;
            let key = VerifyingKey::from_bytes(&vote.signer_pubkey).ok()?;
            if key
                .verify_strict(&digest, &Signature::from_bytes(&vote.signature))
                .is_ok()
            {
                return Some((candidate_context, vote));
            }
        }
    }
    None
}

/// Collects a FINAL live proof; supplied roster is checked locally and must be independently justified by the recipient.
/// Reusable by both GET /v1/verify-current and POST /v1/checkout.
pub async fn collect_live_state_proof(
    state: &AppState,
    context: LiveStateContext,
    deadline: tokio::time::Instant,
) -> Result<LiveStateProof, (StatusCode, &'static str)> {
    if tokio::time::Instant::now() >= deadline {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Deadline exceeded"));
    }

    let is_unoccupied = context.child_lock == [0; 32];
    if is_unoccupied {
        if humoco_proto::live::live_unoccupied_digest(&context).is_err() {
            return Err((StatusCode::BAD_REQUEST, "Invalid unoccupied live context"));
        }
    } else if live_state_digest(&context).is_err() {
        return Err((StatusCode::BAD_REQUEST, "Invalid occupied live context"));
    }

    let Some(pm) = state.peer_manager.as_ref() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Peer manager unavailable"));
    };
    let client_bucket = u16::from_le_bytes([context.parent_lock[0], context.parent_lock[1]]);
    let now_ms = state.net_time_ms();
    let day = state.tier_controller.current_epoch_day_at(now_ms);
    if state
        .tier_controller
        .evaluate_read_quota_with_time(client_bucket, 60, day, 1.0, Some(now_ms))
        .is_err()
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Read quota exceeded"));
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
        return Err((StatusCode::CONFLICT, "Committee mismatch or unstable"));
    }

    let mut groups: std::collections::HashMap<[u8; 32], (LiveStateContext, Vec<AttestationVote>)> =
        std::collections::HashMap::new();

    // Check self as one eligible member using an exact committed local snapshot
    let self_pubkey = *state.identity.node_pubkey();
    if context.committee.contains(&self_pubkey) {
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
            let digest_res = if context.child_lock == [0; 32] {
                humoco_proto::live::live_unoccupied_digest(&context)
            } else {
                live_state_digest(&context)
            };
            if let Ok(digest) = digest_res {
                groups.insert(digest, (context.clone(), vec![vote]));
            }
        } else {
            let local_candidate = {
                let ram = state.engine.hmc_ram.read().await;
                if let Some(entry) = ram.locks.get(&context.lookup_tag) {
                    if entry.layer2_voucher_id == context.voucher_id {
                        let stored_root = ram.voucher_roots.get(&context.voucher_id).copied();
                        let durable_tuple = ram.durable_entries.get(&context.lookup_tag).copied();
                        match (stored_root, durable_tuple) {
                            (Some(root_valid_until), Some((durable_digest, durable_root)))
                                if durable_root == root_valid_until =>
                            {
                                serde_json::to_vec(entry).ok().and_then(|state_bytes| {
                                    let digest = *blake3::hash(&state_bytes).as_bytes();
                                    if digest == durable_digest
                                        && (entry.t_id != context.child_lock
                                            || digest != context.state_digest
                                            || root_valid_until != context.root_valid_until)
                                    {
                                        let mut alt = context.clone();
                                        alt.child_lock = entry.t_id;
                                        alt.state_digest = digest;
                                        alt.root_valid_until = root_valid_until;
                                        Some(alt)
                                    } else {
                                        None
                                    }
                                })
                            }
                            _ => None,
                        }
                    } else {
                        None
                    }
                } else if context.child_lock != [0; 32] {
                    let mut alt = context.clone();
                    alt.child_lock = [0; 32];
                    alt.state_digest = [0; 32];
                    alt.root_valid_until = 0;
                    Some(alt)
                } else {
                    None
                }
            };
            if let Some(alt_ctx) = local_candidate {
                if let Some(vote) = sign_current_state(
                    &state.engine,
                    &state.identity,
                    state.peer_manager.as_ref(),
                    &state.readiness_manager,
                    state.network_id,
                    &alt_ctx,
                )
                .await
                {
                    let digest_res = if alt_ctx.child_lock == [0; 32] {
                        humoco_proto::live::live_unoccupied_digest(&alt_ctx)
                    } else {
                        live_state_digest(&alt_ctx)
                    };
                    if let Ok(digest) = digest_res {
                        groups.insert(digest, (alt_ctx, vec![vote]));
                    }
                }
            }
        }
    }

    let Some(transport) = state.transport.as_ref() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Transport unavailable"));
    };

    let mut jobs = tokio::task::JoinSet::new();
    let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
    let declared_read_ema = state.tier_controller.current_read_ema_credits();
    let net_time_ms = state.net_time_ms();

    for (member, addr) in remotes {
        let q = MemberLiveQuery {
            transport: transport.clone(),
            member_pubkey: member.node_pubkey,
            addr,
            requested_context: context.clone(),
            deadline,
            state_identity: state.identity.clone(),
            net_time_ms,
            declared_write_ema,
            declared_read_ema,
            network_id: state.network_id,
        };
        jobs.spawn(query_member_live_vote(q));
    }

    let mut unresolved_members = jobs.len();
    let mut completed_proof = None;

    let collection_fut = async {
        while let Some(res) = jobs.join_next().await {
            unresolved_members = unresolved_members.saturating_sub(1);
            if let Ok(Some((v_ctx, vote))) = res {
                let digest_res = if v_ctx.child_lock == [0; 32] {
                    humoco_proto::live::live_unoccupied_digest(&v_ctx)
                } else {
                    live_state_digest(&v_ctx)
                };
                if let Ok(digest) = digest_res {
                    let group = groups
                        .entry(digest)
                        .or_insert_with(|| (v_ctx.clone(), Vec::new()));
                    if !group
                        .1
                        .iter()
                        .any(|v| v.signer_pubkey == vote.signer_pubkey)
                    {
                        group.1.push(vote);
                    }
                    if group.1.len() >= 14 {
                        if group.0.child_lock == [0; 32] {
                            let candidate_proof = LiveStateProof {
                                context: group.0.clone(),
                                votes: group.1.clone(),
                                occupancy: LiveSlotOccupancy::Unoccupied,
                            };
                            if verify_live_unoccupied_proof(&candidate_proof, &context).is_ok() {
                                completed_proof = Some(candidate_proof);
                                jobs.abort_all();
                                break;
                            }
                        } else {
                            let candidate_proof = LiveStateProof {
                                context: group.0.clone(),
                                votes: group.1.clone(),
                                occupancy: LiveSlotOccupancy::Occupied,
                            };
                            let pinned_matches = group.0.version == context.version
                                && group.0.network == context.network
                                && group.0.shard_id == context.shard_id
                                && group.0.voucher_id == context.voucher_id
                                && group.0.lookup_tag == context.lookup_tag
                                && group.0.parent_lock == context.parent_lock
                                && group.0.recipient_nonce == context.recipient_nonce
                                && group.0.committee == context.committee;
                            if pinned_matches
                                && verify_live_state_proof(&candidate_proof, &group.0).is_ok()
                            {
                                completed_proof = Some(candidate_proof);
                                jobs.abort_all();
                                break;
                            }
                        }
                    }
                }
            }
            let best_group_votes = groups.values().map(|(_, v)| v.len()).max().unwrap_or(0);
            if best_group_votes + unresolved_members < 14 {
                jobs.abort_all();
                break;
            }
        }
    };

    let _ = tokio::time::timeout_at(deadline, collection_fut).await;
    jobs.abort_all();

    if let Some(proof) = completed_proof {
        Ok(proof)
    } else {
        Err((StatusCode::SERVICE_UNAVAILABLE, "Quorum not reached"))
    }
}

/// Collects a FINAL live proof; supplied roster is checked locally and must be independently justified by the recipient.
/// Enforces a single absolute request deadline and groups candidate votes by exact signed context.
pub async fn verify_current(
    State(state): State<AppState>,
    deadline_ext: Option<axum::extract::Extension<LiveDeadline>>,
    Json(context): Json<LiveStateContext>,
) -> Response {
    let deadline = deadline_ext
        .map(|ext| ext.0 .0)
        .unwrap_or_else(|| tokio::time::Instant::now() + LIVE_PROOF_SERVER_BUDGET);

    match collect_live_state_proof(&state, context, deadline).await {
        Ok(proof) => (StatusCode::OK, Json(proof)).into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    }
}
