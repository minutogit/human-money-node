use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("I/O error at {path}: {source}")]
    IoWithPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration parse error: {0}")]
    ConfigParse(#[from] toml::de::Error),

    #[error("Configuration serialize error: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),

    #[error("Identity error: {0}")]
    Identity(String),

    #[error("CLI error: {0}")]
    Cli(String),

    #[error("Daemon error: {0}")]
    Daemon(String),

    #[error("Storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("Network error: {0}")]
    Network(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Quinn connect error: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),

    #[error("Quinn connection error: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),

    #[error("Quinn write error: {0}")]
    QuinnWrite(#[from] quinn::WriteError),

    #[error("Quinn closed stream error: {0}")]
    QuinnClosedStream(#[from] quinn::ClosedStream),

    #[error("Quinn read error: {0}")]
    QuinnRead(#[from] quinn::ReadError),

    #[error("Quinn read to end error: {0}")]
    QuinnReadToEnd(#[from] quinn::ReadToEndError),
}
