//! Recipient-configured regional authority. Source signatures authenticate a
//! subjective mesh view; the at-most-six Byzantine assumption remains conditional.
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Maximum qualified identities in one bounded regional view.
pub const MAX_MESH_MEMBERS: usize = 4096;
/// Maximum signed-view lifetime, in milliseconds.
pub const MAX_VIEW_LIFETIME_MS: u64 = 60_000;

/// Recipient-owned configuration, persisted independently from payment proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionalMeshPolicy {
    /// Zero mainnet, one testnet.
    pub network: u8,
    /// Explicitly pinned observation sources. Every source must agree on the
    /// requested committee; unavailable or conflicting views fail closed.
    pub source_keys: Vec<[u8; 32]>,
}
impl RegionalMeshPolicy {
    /// Checks bounded, distinct, valid source identities.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.network > 1 || self.source_keys.is_empty() || self.source_keys.len() > 8 {
            return Err("invalid regional source policy");
        }
        let mut seen = std::collections::HashSet::new();
        for key in &self.source_keys {
            if !seen.insert(*key) || VerifyingKey::from_bytes(key).is_err() {
                return Err("invalid regional source identity");
            }
        }
        Ok(())
    }
}

/// Qualified identity/ticket as observed by a pinned regional source. The source
/// must verify ticket work, observed incubation and passive presence before export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionalMeshMember {
    /// Full Ed25519 identity.
    pub node_pubkey: [u8; 32],
    /// Active mature HRW ticket, never an IP-derived identity.
    pub hrw_routing_id: [u8; 32],
}

/// One source's short-lived signed qualified view, without private endpoints or
/// topology edges. This is neither a quorum proof nor unconditional authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegionalMeshView {
    /// Encoding version, currently one.
    pub version: u8,
    /// Zero mainnet, one testnet.
    pub network: u8,
    /// Observation source's full public key.
    pub source_key: [u8; 32],
    /// Source's network-adjusted issue time.
    pub issued_at_ms: u64,
    /// Strict expiry; at most sixty seconds after issue.
    pub valid_until_ms: u64,
    /// Canonically sorted distinct qualified identities.
    pub members: Vec<RegionalMeshMember>,
    /// Source signature over the canonical complete view.
    #[serde(with = "crate::types::serde_bytes_64")]
    pub signature: [u8; 64],
}
impl RegionalMeshView {
    /// Canonical length-prefixed signature preimage, independent of JSON/bincode.
    pub fn digest(&self) -> Result<[u8; 32], &'static str> {
        if self.version != 1
            || self.network > 1
            || self.members.len() > MAX_MESH_MEMBERS
            || self.valid_until_ms <= self.issued_at_ms
            || self.valid_until_ms - self.issued_at_ms > MAX_VIEW_LIFETIME_MS
        {
            return Err("invalid regional view bounds");
        }
        let mut previous = None;
        let mut h = blake3::Hasher::new();
        let domain = b"HUMOCO_V1_REGIONAL_MESH_VIEW";
        h.update(&[domain.len() as u8]);
        h.update(domain);
        h.update(&[self.version, self.network]);
        h.update(&self.source_key);
        h.update(&self.issued_at_ms.to_le_bytes());
        h.update(&self.valid_until_ms.to_le_bytes());
        h.update(&(self.members.len() as u32).to_le_bytes());
        for member in &self.members {
            if previous.is_some_and(|key| key >= member.node_pubkey)
                || VerifyingKey::from_bytes(&member.node_pubkey).is_err()
            {
                return Err("noncanonical regional identities");
            }
            previous = Some(member.node_pubkey);
            h.update(&member.node_pubkey);
            h.update(&member.hrw_routing_id);
        }
        Ok(*h.finalize().as_bytes())
    }
}
fn score(ticket: &[u8; 32], shard: u16) -> [u8; 32] {
    // Existing production HRW encoding. Do not migrate its bytes here.
    let mut h = blake3::Hasher::new();
    h.update(ticket);
    h.update(&shard.to_le_bytes());
    *h.finalize().as_bytes()
}
/// Verifies every configured source and independently derives one frozen top20.
/// Signature validity does not establish the conditional Byzantine fault bound.
pub fn regional_committee(
    policy: &RegionalMeshPolicy,
    views: &[RegionalMeshView],
    shard: u16,
    now_ms: u64,
) -> Result<Vec<[u8; 32]>, &'static str> {
    policy.validate()?;
    if views.len() != policy.source_keys.len() {
        return Err("missing regional source");
    }
    let mut seen = std::collections::HashSet::new();
    let mut agreed = None;
    for view in views {
        if !policy.source_keys.contains(&view.source_key)
            || !seen.insert(view.source_key)
            || view.network != policy.network
            || view.issued_at_ms > now_ms
            || now_ms >= view.valid_until_ms
        {
            return Err("untrusted or stale regional view");
        }
        let digest = view.digest()?;
        let key = VerifyingKey::from_bytes(&view.source_key).map_err(|_| "invalid source key")?;
        key.verify_strict(&digest, &Signature::from_bytes(&view.signature))
            .map_err(|_| "invalid regional source signature")?;
        let mut ranked: Vec<_> = view.members.iter().collect();
        ranked.sort_by(|a, b| {
            score(&b.hrw_routing_id, shard)
                .cmp(&score(&a.hrw_routing_id, shard))
                .then_with(|| a.node_pubkey.cmp(&b.node_pubkey))
        });
        ranked.truncate(20);
        let roster: Vec<_> = ranked.into_iter().map(|m| m.node_pubkey).collect();
        if roster.len() != 20 {
            return Err("regional view cannot establish FINAL committee");
        }
        if agreed.as_ref().is_some_and(|old| old != &roster) {
            return Err("regional sources disagree");
        }
        agreed = Some(roster);
    }
    agreed.ok_or("missing regional view")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn view(source: &SigningKey) -> RegionalMeshView {
        let mut members: Vec<_> = (1u8..=30)
            .map(|i| RegionalMeshMember {
                node_pubkey: SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes(),
                hrw_routing_id: [i; 32],
            })
            .collect();
        members.sort_by_key(|m| m.node_pubkey);
        let mut v = RegionalMeshView {
            version: 1,
            network: 0,
            source_key: source.verifying_key().to_bytes(),
            issued_at_ms: 1_000,
            valid_until_ms: 61_000,
            members,
            signature: [0; 64],
        };
        v.signature = source.sign(&v.digest().unwrap()).to_bytes();
        v
    }
    #[test]
    fn configured_sources_bound_authority_and_disagreement() {
        let a = SigningKey::from_bytes(&[101; 32]);
        let b = SigningKey::from_bytes(&[102; 32]);
        let policy = RegionalMeshPolicy {
            network: 0,
            source_keys: vec![a.verifying_key().to_bytes(), b.verifying_key().to_bytes()],
        };
        let first = view(&a);
        let second = view(&b);
        let roster =
            regional_committee(&policy, &[first.clone(), second.clone()], 42, 2_000).unwrap();
        assert_eq!(roster.len(), 20);
        assert!(regional_committee(&policy, std::slice::from_ref(&first), 42, 2_000).is_err());
        let mut wrong = second.clone();
        wrong.members[0].hrw_routing_id = [255; 32];
        assert!(regional_committee(&policy, &[first.clone(), wrong.clone()], 42, 2_000).is_err());
        wrong.members.remove(0);
        wrong.signature = b.sign(&wrong.digest().unwrap()).to_bytes();
        // Remove one actual top20 identity while retaining at least twenty valid members.
        wrong.members.retain(|m| m.node_pubkey != roster[0]);
        wrong.signature = b.sign(&wrong.digest().unwrap()).to_bytes();
        assert!(regional_committee(&policy, &[first.clone(), wrong], 42, 2_000).is_err());
        assert!(regional_committee(&policy, &[first.clone(), second.clone()], 42, 61_000).is_err());
        let other_policy = RegionalMeshPolicy {
            network: 1,
            ..policy
        };
        assert!(regional_committee(&other_policy, &[first, second], 42, 2_000).is_err());
    }
}
