use std::sync::Arc;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::NodeError;
use crate::identity::NodeIdentity;

pub const ALPN_HUMOCO_L2: &[u8] = b"humoco-l2-mainnet";

/// Returns the ALPN protocol identifier for the given network.
/// - Mainnet => `humoco-l2-mainnet`
/// - Testnet => `humoco-l2-testnet`
pub fn get_alpn_for_network(network_id: humoco_sim_core::types::NetworkId) -> &'static [u8] {
    match network_id {
        humoco_sim_core::types::NetworkId::Mainnet => b"humoco-l2-mainnet",
        humoco_sim_core::types::NetworkId::Testnet => b"humoco-l2-testnet",
    }
}

/// Ensure the default rustls crypto provider is installed (ring).
pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generates a self-signed X.509 certificate for TLS 1.3 based on the given NodeIdentity.
pub fn generate_node_certificate(
    identity: &NodeIdentity,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), NodeError> {
    init_crypto_provider();

    let pkcs8_doc = identity
        .signing_key()
        .to_pkcs8_der()
        .map_err(|e| NodeError::Tls(format!("Failed to encode PKCS#8 DER private key: {}", e)))?;

    let pkcs8_key_der = PrivatePkcs8KeyDer::from(pkcs8_doc.as_bytes().to_vec());
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key_der, &rcgen::PKCS_ED25519)
        .map_err(|e| NodeError::Tls(format!("Failed to parse rcgen keypair from PKCS#8 DER: {}", e)))?;

    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        identity.node_id_hex(),
    ])
    .map_err(|e| NodeError::Tls(format!("Failed to create certificate params: {}", e)))?;

    params.is_ca = rcgen::IsCa::NoCa;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| NodeError::Tls(format!("Failed to generate self-signed cert: {}", e)))?;

    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_doc.as_bytes().to_vec()));

    Ok((cert_der, key_der))
}

/// Permissive P2P certificate verifier that accepts self-signed peer certificates.
#[derive(Debug, Default)]
pub struct P2pCertVerifier;

impl P2pCertVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl rustls::client::danger::ServerCertVerifier for P2pCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Permissive P2P client certificate verifier that requests and accepts self-signed Ed25519 peer certificates.
#[derive(Debug, Default)]
pub struct P2pClientCertVerifier;

impl P2pClientCertVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl rustls::server::danger::ClientCertVerifier for P2pClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Extracts the Ed25519 public key and BLAKE3 Node ID from an X.509 DER certificate.
pub fn extract_peer_node_id(
    cert_der: &[u8],
) -> Result<([u8; 32], ed25519_dalek::VerifyingKey), NodeError> {
    // RFC 8410: Ed25519 SubjectPublicKeyInfo prefix in ASN.1 DER:
    // SEQUENCE (0x30, 0x05) { OID 1.3.101.112 (0x06, 0x03, 0x2b, 0x65, 0x70) }
    // BIT STRING (0x03, 0x21, 0x00) -> followed by 32 raw public key bytes.
    const ED25519_SPKI_PREFIX: [u8; 10] = [
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let pos = cert_der
        .windows(ED25519_SPKI_PREFIX.len())
        .position(|w| w == ED25519_SPKI_PREFIX)
        .ok_or_else(|| {
            NodeError::Tls("No valid Ed25519 SubjectPublicKeyInfo found in peer certificate".into())
        })?;

    let pubkey_offset = pos + ED25519_SPKI_PREFIX.len();
    if pubkey_offset + 32 > cert_der.len() {
        return Err(NodeError::Tls("Truncated Ed25519 public key in certificate".into()));
    }

    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&cert_der[pubkey_offset..pubkey_offset + 32]);

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| NodeError::Tls(format!("Invalid Ed25519 public key in certificate: {}", e)))?;

    let node_id = *blake3::hash(verifying_key.as_bytes()).as_bytes();
    Ok((node_id, verifying_key))
}

/// Helper to extract peer node ID and verifying key directly from a Quinn Connection.
pub fn extract_peer_identity_from_connection(
    conn: &quinn::Connection,
) -> Option<([u8; 32], ed25519_dalek::VerifyingKey)> {
    let peer_identity = conn.peer_identity()?;
    let certs = peer_identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    let cert = certs.first()?;
    extract_peer_node_id(cert.as_ref()).ok()
}

/// Builds a Quinn ServerConfig from a NodeIdentity, enforcing client certificate authentication via P2pClientCertVerifier.
pub fn build_quinn_server_config(identity: &NodeIdentity) -> Result<quinn::ServerConfig, NodeError> {
    build_quinn_server_config_with_network(identity, humoco_sim_core::types::NetworkId::default())
}

/// Builds a Quinn ServerConfig for a specific network (ALPN varies by NetworkId).
pub fn build_quinn_server_config_with_network(
    identity: &NodeIdentity,
    network_id: humoco_sim_core::types::NetworkId,
) -> Result<quinn::ServerConfig, NodeError> {
    let (cert_der, key_der) = generate_node_certificate(identity)?;

    let client_cert_verifier = Arc::new(P2pClientCertVerifier::new());
    let mut server_tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| NodeError::Tls(format!("Failed to build rustls ServerConfig: {}", e)))?;

    server_tls_config.alpn_protocols = vec![get_alpn_for_network(network_id).to_vec()];

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config)
        .map_err(|e| NodeError::Tls(format!("Failed to build QuicServerConfig: {}", e)))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .map_err(|e| NodeError::Tls(format!("Invalid idle timeout: {}", e)))?,
    ));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

/// Builds a Quinn ClientConfig for connecting to P2P peers with the node's own identity certificate.
pub fn build_quinn_client_config_with_identity(
    identity: &NodeIdentity,
) -> Result<quinn::ClientConfig, NodeError> {
    build_quinn_client_config_with_identity_and_network(
        identity,
        humoco_sim_core::types::NetworkId::default(),
    )
}

/// Builds a Quinn ClientConfig with identity for a specific network.
pub fn build_quinn_client_config_with_identity_and_network(
    identity: &NodeIdentity,
    network_id: humoco_sim_core::types::NetworkId,
) -> Result<quinn::ClientConfig, NodeError> {
    init_crypto_provider();

    let (cert_der, key_der) = generate_node_certificate(identity)?;
    let verifier = Arc::new(P2pCertVerifier::new());
    let mut client_tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert_der], key_der)
        .map_err(|e| NodeError::Tls(format!("Failed to build rustls ClientConfig with client auth: {}", e)))?;

    client_tls_config.alpn_protocols = vec![get_alpn_for_network(network_id).to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls_config)
        .map_err(|e| NodeError::Tls(format!("Failed to build QuicClientConfig: {}", e)))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .map_err(|e| NodeError::Tls(format!("Invalid idle timeout: {}", e)))?,
    ));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Alias for `build_quinn_client_config_with_identity_and_network` (compatibility).
pub fn build_quinn_client_config_with_identity_with_network(
    identity: &NodeIdentity,
    network_id: humoco_sim_core::types::NetworkId,
) -> Result<quinn::ClientConfig, NodeError> {
    build_quinn_client_config_with_identity_and_network(identity, network_id)
}

/// Builds a Quinn ClientConfig for connecting to P2P peers without client authentication (fallback).
pub fn build_quinn_client_config() -> Result<quinn::ClientConfig, NodeError> {
    build_quinn_client_config_with_network(humoco_sim_core::types::NetworkId::default())
}

/// Builds a Quinn ClientConfig without client authentication for a specific network.
pub fn build_quinn_client_config_with_network(
    network_id: humoco_sim_core::types::NetworkId,
) -> Result<quinn::ClientConfig, NodeError> {
    init_crypto_provider();

    let verifier = Arc::new(P2pCertVerifier::new());
    let mut client_tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    client_tls_config.alpn_protocols = vec![get_alpn_for_network(network_id).to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls_config)
        .map_err(|e| NodeError::Tls(format!("Failed to build QuicClientConfig: {}", e)))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .map_err(|e| NodeError::Tls(format!("Invalid idle timeout: {}", e)))?,
    ));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_generation() {
        let identity = NodeIdentity::generate();
        let (cert, _key) = generate_node_certificate(&identity).expect("cert generation");
        assert!(!cert.is_empty());
    }

    #[test]
    fn test_extract_peer_node_id() {
        let identity = NodeIdentity::generate();
        let (cert, _key) = generate_node_certificate(&identity).expect("cert generation");

        let (extracted_node_id, extracted_vk) =
            extract_peer_node_id(cert.as_ref()).expect("extract peer node id");

        assert_eq!(extracted_node_id, *identity.node_id());
        assert_eq!(extracted_vk, *identity.verifying_key());
    }

    #[test]
    fn test_quinn_configs_creation() {
        let identity = NodeIdentity::generate();
        let server_config = build_quinn_server_config(&identity);
        assert!(server_config.is_ok());

        let client_config_no_auth = build_quinn_client_config();
        assert!(client_config_no_auth.is_ok());

        let client_config_with_id = build_quinn_client_config_with_identity(&identity);
        assert!(client_config_with_id.is_ok());
    }
}
