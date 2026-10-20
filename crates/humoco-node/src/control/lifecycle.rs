//! Local process-instance-bound shutdown completion evidence (not consensus state).
use crate::error::NodeError;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Evidence identifying the exact daemon instance and its private completion file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShutdownIdentity {
    pub pid: u32,
    pub process_start: String,
    pub nonce: String,
    pub completion_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct Completion {
    identity: ShutdownIdentity,
    clean: bool,
}

/// Instance-bound local completion writer. A clean marker is written after run resources drop.
pub struct ShutdownLifecycle {
    pub identity: ShutdownIdentity,
}

/// Returns Linux process state and immutable start ticks; PID alone is insufficient.
pub fn process_instance(pid: u32) -> Result<Option<(char, String)>, NodeError> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(NodeError::IoWithPath { path, source: e }),
    };
    let (_, fields) = raw
        .rsplit_once(')')
        .ok_or_else(|| NodeError::Daemon("invalid process identity".into()))?;
    let parts: Vec<_> = fields.split_whitespace().collect();
    let state = parts
        .first()
        .and_then(|s| s.chars().next())
        .ok_or_else(|| NodeError::Daemon("missing process state".into()))?;
    let start = parts
        .get(19)
        .ok_or_else(|| NodeError::Daemon("missing process start identity".into()))?
        .to_string();
    Ok(Some((state, start)))
}

impl ShutdownLifecycle {
    /// Creates a unique private completion destination before serving control requests.
    pub fn new(socket: &Path) -> Result<Self, NodeError> {
        let pid = std::process::id();
        let (_, process_start) = process_instance(pid)?
            .ok_or_else(|| NodeError::Daemon("cannot identify daemon process".into()))?;
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        let completion_path = socket.with_extension("stop.json");
        Ok(Self {
            identity: ShutdownIdentity {
                pid,
                process_start,
                nonce,
                completion_path,
            },
        })
    }

    /// Records the actual teardown outcome. Never call before all run resources have dropped.
    pub fn complete(&self, clean: bool) -> Result<(), NodeError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let temporary = self
            .identity
            .completion_path
            .with_extension(format!("{}.tmp", self.identity.nonce));
        let mut file = options.open(&temporary)?;
        let bytes = serde_json::to_vec(&Completion {
            identity: self.identity.clone(),
            clean,
        })
        .map_err(|e| NodeError::Daemon(format!("cannot encode shutdown completion: {e}")))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(temporary, &self.identity.completion_path)?;
        Ok(())
    }
}

/// Checks a bounded private completion record and the target's actual process termination.
pub fn completed_cleanly(identity: &ShutdownIdentity, socket: &Path) -> Result<bool, NodeError> {
    if identity.completion_path.parent() != socket.parent()
        || identity.nonce.len() != 32
        || !identity.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        || identity.completion_path != socket.with_extension("stop.json")
    {
        return Err(NodeError::Daemon(
            "invalid shutdown completion destination".into(),
        ));
    }
    let bytes = match std::fs::File::open(&identity.completion_path).and_then(|file| {
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        Ok(bytes)
    }) {
        Ok(bytes) if bytes.len() <= 4096 => bytes,
        Ok(_) => {
            return Err(NodeError::Daemon(
                "oversized shutdown completion record".into(),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let completion: Completion = serde_json::from_slice(&bytes)
        .map_err(|e| NodeError::Daemon(format!("invalid shutdown completion: {e}")))?;
    if &completion.identity != identity {
        return Ok(false);
    }
    if !completion.clean {
        return Err(NodeError::Daemon(
            "daemon shutdown was incomplete or unverified".into(),
        ));
    }
    match process_instance(identity.pid)? {
        Some((state, start)) if start == identity.process_start && state != 'Z' && state != 'X' => {
            Ok(false)
        }
        _ => Ok(true),
    }
}
