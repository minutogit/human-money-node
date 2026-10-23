//! Authenticated passive HTTP publications on the existing heartbeat stream.
use crate::identity::NodeIdentity;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayAdvertisement {
    pub version: u8,
    pub network: u8,
    pub node_pubkey: [u8; 32],
    pub issued_at_ms: u64,
    pub valid_until_ms: u64,
    pub urls: Vec<String>,
    #[serde(with = "super::framing::serde_sig_64")]
    pub signature: [u8; 64],
}
impl GatewayAdvertisement {
    fn digest(&self) -> Option<[u8; 32]> {
        if self.version != 1
            || self.network > 1
            || self.urls.len() > 16
            || self.valid_until_ms <= self.issued_at_ms
            || self.valid_until_ms - self.issued_at_ms > 7_200_000
        {
            return None;
        }
        let mut h = blake3::Hasher::new();
        let domain = b"HUMOCO_V1_GATEWAY_ADVERTISEMENT";
        h.update(&[domain.len() as u8]);
        h.update(domain);
        h.update(&[self.version, self.network]);
        h.update(&self.node_pubkey);
        h.update(&self.issued_at_ms.to_le_bytes());
        h.update(&self.valid_until_ms.to_le_bytes());
        h.update(&(self.urls.len() as u16).to_le_bytes());
        for url in &self.urls {
            if url.len() > 2048 || !crate::config::is_publishable_gateway_url(url) {
                return None;
            }
            h.update(&(url.len() as u16).to_le_bytes());
            h.update(url.as_bytes());
        }
        Some(*h.finalize().as_bytes())
    }
    pub fn signed(
        identity: &NodeIdentity,
        network: u8,
        urls: Vec<String>,
        now: u64,
    ) -> Option<Self> {
        let mut ad = Self {
            version: 1,
            network,
            node_pubkey: *identity.node_pubkey(),
            issued_at_ms: now,
            valid_until_ms: now.checked_add(7_200_000)?,
            urls,
            signature: [0; 64],
        };
        ad.signature = identity.signing_key().sign(&ad.digest()?).to_bytes();
        Some(ad)
    }
    pub fn verify(&self, expected: &[u8; 32], network: u8, now: u64) -> bool {
        if self.node_pubkey != *expected
            || self.network != network
            || self.issued_at_ms > now.saturating_add(30_000)
            || self.valid_until_ms <= now
        {
            return false;
        }
        let (Some(digest), Ok(key)) = (
            self.digest(),
            ed25519_dalek::VerifyingKey::from_bytes(expected),
        ) else {
            return false;
        };
        key.verify_strict(
            &digest,
            &ed25519_dalek::Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}
