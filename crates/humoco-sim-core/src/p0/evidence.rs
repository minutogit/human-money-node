use super::admission::verify;
use super::{bytes, hash, Error, Id, Key, Mode, View};
use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot {
    pub network: Id,
    pub root: Id,
    pub output: Id,
}
impl Slot {
    pub(crate) fn encode(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.network);
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&self.output);
    }
    pub fn shard(&self) -> u16 {
        u16::from_le_bytes([self.output[0], self.output[1]])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootAnchor {
    pub network: Id,
    pub owner: Key,
    pub nonce: u64,
    pub valid_until: u64,
    pub signature: [u8; 64],
}
impl RootAnchor {
    pub fn issue(owner: &SigningKey, network: Id, nonce: u64, valid_until: u64) -> Self {
        let mut r = Self {
            network,
            owner: owner.verifying_key().to_bytes(),
            nonce,
            valid_until,
            signature: [0; 64],
        };
        r.signature = owner
            .sign(&bytes(b"HUMOCO_P0_SIM_ROOT", &r.body()))
            .to_bytes();
        r
    }
    fn body(&self) -> Vec<u8> {
        let mut b = self.network.to_vec();
        b.extend_from_slice(&self.owner);
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.extend_from_slice(&self.valid_until.to_le_bytes());
        b
    }
    pub fn id(&self) -> Id {
        hash(b"HUMOCO_P0_SIM_ROOT_ID", &self.body())
    }
    pub fn verify(&self) -> Result<(), Error> {
        verify(
            self.owner,
            b"HUMOCO_P0_SIM_ROOT",
            &self.body(),
            self.signature,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Child {
    pub owner: Key,
    pub commitment: Id,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub slot: Slot,
    pub root_valid_until: u64,
    pub owner: Key,
    pub children: Vec<Child>,
    pub nonce: u64,
    pub signature: [u8; 64],
}
impl Intent {
    pub fn issue(
        owner: &SigningKey,
        slot: Slot,
        root_valid_until: u64,
        children: Vec<Child>,
        nonce: u64,
    ) -> Self {
        let mut t = Self {
            slot,
            root_valid_until,
            owner: owner.verifying_key().to_bytes(),
            children,
            nonce,
            signature: [0; 64],
        };
        t.signature = owner
            .sign(&bytes(b"HUMOCO_P0_SIM_OWNER_INTENT", &t.body()))
            .to_bytes();
        t
    }
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        self.slot.encode(&mut b);
        b.extend_from_slice(&self.root_valid_until.to_le_bytes());
        b.extend_from_slice(&self.owner);
        b.extend_from_slice(&(self.children.len() as u32).to_le_bytes());
        for child in &self.children {
            b.extend_from_slice(&child.owner);
            b.extend_from_slice(&child.commitment);
        }
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b
    }
    pub fn id(&self) -> Id {
        hash(b"HUMOCO_P0_SIM_CANONICAL_INTENT", &self.body())
    }
    pub fn verify(&self) -> Result<(), Error> {
        if self.children.is_empty()
            || self.children.len() > 1024
            || self.children.iter().collect::<BTreeSet<_>>().len() != self.children.len()
        {
            return Err(Error::InvalidIntent);
        }
        verify(
            self.owner,
            b"HUMOCO_P0_SIM_OWNER_INTENT",
            &self.body(),
            self.signature,
        )
    }
    pub fn output(&self, index: usize) -> Result<Id, Error> {
        if index >= self.children.len() {
            return Err(Error::InvalidIntent);
        }
        let mut b = self.id().to_vec();
        b.extend_from_slice(&(index as u32).to_le_bytes());
        Ok(hash(b"HUMOCO_P0_SIM_OUTPUT", &b))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub node: Key,
    pub slot: Slot,
    pub spend: Id,
    pub root_valid_until: u64,
    pub mode: Mode,
    pub view_id: Id,
    pub issued_at: u64,
    pub signature: [u8; 64],
}
impl Approval {
    /// Bypasses the honest durable-choice policy, for adversarial fixtures only.
    pub fn issue_unchecked(key: &SigningKey, intent: &Intent, view: &View, now: u64) -> Self {
        let mut a = Self {
            node: key.verifying_key().to_bytes(),
            slot: intent.slot,
            spend: intent.id(),
            root_valid_until: intent.root_valid_until,
            mode: view.mode,
            view_id: view.id,
            issued_at: now,
            signature: [0; 64],
        };
        a.signature = key
            .sign(&bytes(b"HUMOCO_P0_SIM_LOCK_APPROVAL", &a.body()))
            .to_bytes();
        a
    }
    fn body(&self) -> Vec<u8> {
        let mut b = self.node.to_vec();
        self.slot.encode(&mut b);
        b.extend_from_slice(&self.spend);
        b.extend_from_slice(&self.root_valid_until.to_le_bytes());
        b.push(self.mode as u8);
        b.extend_from_slice(&self.view_id);
        b.extend_from_slice(&self.issued_at.to_le_bytes());
        b
    }
    pub fn verify(&self) -> Result<(), Error> {
        verify(
            self.node,
            b"HUMOCO_P0_SIM_LOCK_APPROVAL",
            &self.body(),
            self.signature,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub intent: Intent,
    pub view: View,
    pub approvals: Vec<Approval>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub node: Key,
    pub slot: Slot,
    pub winner: Id,
    pub support: u8,
    pub knowledge: Id,
    pub signature: [u8; 64],
}
impl Observation {
    pub(crate) fn issue(
        key: &SigningKey,
        slot: Slot,
        winner: Id,
        support: u8,
        knowledge: Id,
    ) -> Self {
        let mut o = Self {
            node: key.verifying_key().to_bytes(),
            slot,
            winner,
            support,
            knowledge,
            signature: [0; 64],
        };
        o.signature = key
            .sign(&bytes(b"HUMOCO_P0_SIM_CANONICAL_OBSERVATION", &o.body()))
            .to_bytes();
        o
    }
    fn body(&self) -> Vec<u8> {
        let mut b = self.node.to_vec();
        self.slot.encode(&mut b);
        b.extend_from_slice(&self.winner);
        b.push(self.support);
        b.extend_from_slice(&self.knowledge);
        b
    }
}

pub fn verify_observation(o: &Observation) -> Result<(), Error> {
    verify(
        o.node,
        b"HUMOCO_P0_SIM_CANONICAL_OBSERVATION",
        &o.body(),
        o.signature,
    )
}

pub fn verify_node_equivocation(a: &Approval, b: &Approval) -> Result<Key, Error> {
    a.verify()?;
    b.verify()?;
    if a.node != b.node || a.slot != b.slot || a.spend == b.spend {
        return Err(Error::InvalidEvidence);
    }
    Ok(a.node)
}

pub fn verify_owner_double_spend(a: &Intent, b: &Intent) -> Result<Key, Error> {
    a.verify()?;
    b.verify()?;
    if a.owner != b.owner || a.slot != b.slot || a.id() == b.id() {
        return Err(Error::InvalidEvidence);
    }
    Ok(a.owner)
}
