#![allow(dead_code)]

//! Deterministic fixtures, not a production admission or transport implementation.
//! Every observer learns tickets through its own configured F2F friend and records
//! its own heartbeat/reachability events. No gateway installs a catalog.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use humoco_sim_core::p0::*;

pub struct Fixture {
    pub keys: Vec<SigningKey>,
    pub owner: SigningKey,
    pub network: Id,
    pub now: u64,
}

impl Fixture {
    pub fn new(count: usize) -> Self {
        let keys = (0..count)
            .map(|index| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
                seed[31] = 0x50;
                SigningKey::from_bytes(&seed)
            })
            .collect();
        Self {
            keys,
            owner: SigningKey::from_bytes(&[0x91; 32]),
            network: *blake3::hash(b"P0-SIM-1 deterministic network").as_bytes(),
            now: 3 * DAY_MS,
        }
    }

    pub fn key(&self, index: usize) -> Key {
        self.keys[index].verifying_key().to_bytes()
    }

    pub fn catalog(&self, observer: usize, indices: &[usize]) -> Context {
        let friend = self.key(observer);
        let mut context = Context::new(self.network, friend, BTreeSet::from([friend]));
        for &index in indices {
            let ticket = Ticket::issue(&self.keys[index], index as u64, 0, 1);
            context
                .learn(ticket, friend, 0, true)
                .expect("authenticated learning");
        }
        for hour in 0..=24 {
            for &index in indices {
                context
                    .observe_heartbeat(self.key(index), hour * HOUR_MS)
                    .expect("locally observed authenticated heartbeat");
            }
        }
        // Advance actual local observations at intervals shorter than the lease;
        // merely setting a remote claimed date would not establish continuity.
        let mut tick = DAY_MS;
        while tick <= self.now {
            for &index in indices {
                if tick.is_multiple_of(HOUR_MS) && tick > DAY_MS {
                    context
                        .observe_heartbeat(self.key(index), tick)
                        .expect("continued local presence");
                }
                context
                    .refresh_reachability(self.key(index), tick)
                    .expect("fresh authenticated simulated direct response");
            }
            context.update_population(tick);
            tick += 60_000;
        }
        context
    }

    pub fn root(&self, tag: u64) -> RootAnchor {
        RootAnchor::issue(&self.owner, self.network, tag, self.now + 365 * DAY_MS)
    }

    pub fn intent(&self, root: &RootAnchor, tag: u64) -> Intent {
        self.spend(root, root.id(), vec![tag], tag)
    }

    pub fn spend(&self, root: &RootAnchor, output: Id, children: Vec<u64>, nonce: u64) -> Intent {
        Intent::issue(
            &self.owner,
            Slot {
                network: self.network,
                root: root.id(),
                output,
            },
            root.valid_until,
            children
                .into_iter()
                .map(|tag| Child {
                    owner: self.owner.verifying_key().to_bytes(),
                    commitment: *blake3::hash(&tag.to_le_bytes()).as_bytes(),
                })
                .collect(),
            nonce,
        )
    }

    pub fn child_intent(
        &self,
        root: &RootAnchor,
        parent: &Intent,
        index: usize,
        tag: u64,
    ) -> Intent {
        self.spend(
            root,
            parent.output(index).expect("existing parent output"),
            vec![tag],
            tag,
        )
    }

    pub fn registry(&self, observer: usize, indices: &[usize], roots: &[RootAnchor]) -> Registry {
        let mut context = self.catalog(observer, indices);
        for root in roots {
            context
                .register_root(root.clone())
                .expect("authenticated root");
        }
        Registry::new(context)
    }

    /// Constructs authentic independent-issuance evidence. This deliberately does
    /// not claim the signers' durable histories; honest live paths use Signer.
    pub fn receipt(&self, view: &View, intent: &Intent, indices: &[usize]) -> Receipt {
        Receipt {
            intent: intent.clone(),
            view: view.clone(),
            approvals: indices
                .iter()
                .map(|&index| Approval::issue_unchecked(&self.keys[index], intent, view, self.now))
                .collect(),
        }
    }

    pub fn signer_indices(&self, view: &View) -> Vec<usize> {
        view.roster
            .iter()
            .map(|key| {
                self.keys
                    .iter()
                    .position(|signer| signer.verifying_key().to_bytes() == *key)
                    .expect("view identity belongs to fixture")
            })
            .collect()
    }

    pub fn receipt_local(
        &self,
        registry: &mut Registry,
        intent: &Intent,
        indices: &[usize],
    ) -> Receipt {
        let view = registry
            .context
            .freeze_view(intent.slot.shard(), self.now)
            .expect("independent locally selected view for consumed output shard");
        self.receipt(&view, intent, indices)
    }

    /// Register an independently configured observation provider. This is an
    /// explicit local trust capability, never part of a receipt/gateway payload.
    pub fn recognize(
        &self,
        receiver: &mut Registry,
        provider: &Registry,
        view: &View,
        provider_index: usize,
    ) {
        receiver.context.trust_observer(self.key(provider_index));
        receiver
            .context
            .recognize_cut(&provider.context, view)
            .expect("independently authenticated historical observer cut");
    }
}

/// A finite, reproducible transport event model. Cross-component messages are
/// withheld until an explicit reconnect; this is not a QUIC/wire test.
pub struct SimNetwork {
    components: Vec<usize>,
    pending: Vec<(usize, usize, Receipt)>,
    pub trace: Vec<String>,
    pub now: u64,
}

impl SimNetwork {
    pub fn new(nodes: usize, now: u64) -> Self {
        Self {
            components: vec![0; nodes],
            pending: Vec::new(),
            trace: vec!["connected".into()],
            now,
        }
    }

    pub fn partition(&mut self, groups: &[&[usize]]) {
        for (component, group) in groups.iter().enumerate() {
            for &node in group.iter() {
                self.components[node] = component;
            }
        }
        self.trace.push(format!("partition at {}", self.now));
    }

    pub fn advance(&mut self, elapsed: u64) {
        self.now += elapsed;
        self.trace
            .push(format!("advance {elapsed} to {}", self.now));
    }

    pub fn connected(&self, source: usize, target: usize) -> bool {
        self.components[source] == self.components[target]
    }

    pub fn send(&mut self, source: usize, target: usize, receipt: Receipt) -> Option<Receipt> {
        if self.connected(source, target) {
            self.trace.push(format!("deliver {source}->{target}"));
            Some(receipt)
        } else {
            self.trace.push(format!("withhold {source}->{target}"));
            self.pending.push((source, target, receipt));
            None
        }
    }

    pub fn reconnect(&mut self) -> Vec<(usize, Receipt)> {
        self.components.fill(0);
        self.trace.push(format!("reconnect at {}", self.now));
        self.pending
            .drain(..)
            .map(|(_, target, receipt)| (target, receipt))
            .collect()
    }
}
