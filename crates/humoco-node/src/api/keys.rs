//! Key parsing and display normalization utilities for API endpoints and admin controls.

use crate::error::NodeError;

/// Parses a public key from various input representations:
/// - 64 hex characters (with optional "0x" / "0X" prefix)
/// - Base58 encoded 32-byte public key
/// - Peering string format `<pubkey>@<ip_or_host>:<port>`
///
/// Leading and trailing whitespace is automatically trimmed.
pub fn parse_pubkey(input: &str) -> Result<[u8; 32], NodeError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(NodeError::Identity(
            "Public key string cannot be empty".to_string(),
        ));
    }

    // Handle peering string format: <pubkey>@<ip_or_host>:<port>
    let pubkey_str = if let Some((pk_part, endpoint)) = trimmed.split_once('@') {
        let pk_trimmed = pk_part.trim();
        let ep_trimmed = endpoint.trim();
        if pk_trimmed.is_empty() {
            return Err(NodeError::Identity(
                "Peering string missing public key before '@'".to_string(),
            ));
        }
        if ep_trimmed.is_empty() {
            return Err(NodeError::Identity(
                "Peering string missing endpoint after '@'".to_string(),
            ));
        }
        pk_trimmed
    } else {
        trimmed
    };

    // Strip optional 0x/0X prefix for hex representation
    let stripped_hex = pubkey_str
        .strip_prefix("0x")
        .or_else(|| pubkey_str.strip_prefix("0X"))
        .unwrap_or(pubkey_str);

    // 1. Check if it's a 64-character hex string
    if stripped_hex.len() == 64 {
        if let Ok(vec) = hex::decode(stripped_hex) {
            if vec.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&vec);
                return Ok(arr);
            }
        }
    }

    // 2. Try Base58 decoding
    if let Ok(vec) = bs58::decode(pubkey_str).into_vec() {
        if vec.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&vec);
            return Ok(arr);
        } else {
            return Err(NodeError::Identity(format!(
                "Decoded Base58 public key has invalid byte length: expected 32, got {}",
                vec.len()
            )));
        }
    }

    // 3. Neither valid hex nor Base58
    Err(NodeError::Identity(format!(
        "Invalid public key format: '{}' is neither valid 64-char hex nor valid 32-byte Base58",
        pubkey_str
    )))
}

/// Normalizes a 32-byte public key into `(hex_string, base58_string)`.
pub fn normalize_pubkey_display(pubkey: &[u8; 32]) -> (String, String) {
    let hex_str = hex::encode(pubkey);
    let bs58_str = bs58::encode(pubkey).into_string();
    (hex_str, bs58_str)
}

/// Parses and validates a client or admin token.
///
/// Trims whitespace, verifies non-empty, and checks sensible length (8..=128).
pub fn parse_client_token(input: &str) -> Result<String, NodeError> {
    let token = input.trim();
    if token.is_empty() {
        return Err(NodeError::Identity(
            "Client token cannot be empty".to_string(),
        ));
    }
    if token.len() < 8 || token.len() > 128 {
        return Err(NodeError::Identity(format!(
            "Client token length must be between 8 and 128 characters, got {}",
            token.len()
        )));
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PUBKEY: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];

    #[test]
    fn test_parse_pubkey_valid_hex() {
        let hex_lower = hex::encode(SAMPLE_PUBKEY);
        assert_eq!(parse_pubkey(&hex_lower).unwrap(), SAMPLE_PUBKEY);

        let hex_upper = hex_lower.to_uppercase();
        assert_eq!(parse_pubkey(&hex_upper).unwrap(), SAMPLE_PUBKEY);

        // With 0x / 0X prefix
        let with_prefix_lower = format!("0x{}", hex_lower);
        assert_eq!(parse_pubkey(&with_prefix_lower).unwrap(), SAMPLE_PUBKEY);
        let with_prefix_upper = format!("0X{}", hex_upper);
        assert_eq!(parse_pubkey(&with_prefix_upper).unwrap(), SAMPLE_PUBKEY);

        // With whitespace
        let with_spaces = format!("  \n  {} \t ", hex_lower);
        assert_eq!(parse_pubkey(&with_spaces).unwrap(), SAMPLE_PUBKEY);
    }

    #[test]
    fn test_parse_pubkey_valid_base58() {
        let bs58_str = bs58::encode(SAMPLE_PUBKEY).into_string();
        assert_eq!(parse_pubkey(&bs58_str).unwrap(), SAMPLE_PUBKEY);

        // With whitespace
        let with_spaces = format!("  \t {} \n ", bs58_str);
        assert_eq!(parse_pubkey(&with_spaces).unwrap(), SAMPLE_PUBKEY);
    }

    #[test]
    fn test_parse_pubkey_peering_string() {
        let bs58_str = bs58::encode(SAMPLE_PUBKEY).into_string();
        let hex_str = hex::encode(SAMPLE_PUBKEY);

        // Base58 peering string
        let peering_b58 = format!("{}@127.0.0.1:9090", bs58_str);
        assert_eq!(parse_pubkey(&peering_b58).unwrap(), SAMPLE_PUBKEY);

        // Hex peering string with DNS host
        let peering_hex = format!("{}@node1.humoco.network:9090", hex_str);
        assert_eq!(parse_pubkey(&peering_hex).unwrap(), SAMPLE_PUBKEY);

        // With whitespace around components
        let peering_spaces = format!("  {} @ 10.0.0.1:9090  ", bs58_str);
        assert_eq!(parse_pubkey(&peering_spaces).unwrap(), SAMPLE_PUBKEY);

        // Invalid peering string: missing pubkey
        assert!(parse_pubkey("@127.0.0.1:9090").is_err());
        // Invalid peering string: missing endpoint
        assert!(parse_pubkey(&format!("{}@", bs58_str)).is_err());
    }

    #[test]
    fn test_parse_pubkey_invalid_length() {
        // Empty
        assert!(parse_pubkey("").is_err());
        assert!(parse_pubkey("   \n\t ").is_err());

        // Too short hex
        let short_hex = "1234567890abcdef";
        assert!(parse_pubkey(short_hex).is_err());

        // 62 chars hex
        let hex_62 = &hex::encode(SAMPLE_PUBKEY)[..62];
        assert!(parse_pubkey(hex_62).is_err());

        // 66 chars hex
        let hex_66 = format!("{}abcd", hex::encode(SAMPLE_PUBKEY));
        assert!(parse_pubkey(&hex_66).is_err());

        // Base58 that decodes to 16 bytes instead of 32
        let b58_16 = bs58::encode(&[0x42u8; 16]).into_string();
        let err = parse_pubkey(&b58_16).unwrap_err();
        match err {
            NodeError::Identity(msg) => {
                assert!(msg.contains("invalid byte length"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_parse_pubkey_garbage_and_malformed() {
        assert!(parse_pubkey("this-is-not-a-valid-key!").is_err());
        assert!(parse_pubkey("???????$$$$$$$$$$$$$$$$$$$$$").is_err());
        assert!(parse_pubkey("12345678901234567890123456789012345678901234567890123456789012zz").is_err());
    }

    #[test]
    fn test_normalize_pubkey_display() {
        let (hex_str, bs58_str) = normalize_pubkey_display(&SAMPLE_PUBKEY);
        assert_eq!(hex_str, hex::encode(SAMPLE_PUBKEY));
        assert_eq!(bs58_str, bs58::encode(SAMPLE_PUBKEY).into_string());

        // Roundtrip parsing
        assert_eq!(parse_pubkey(&hex_str).unwrap(), SAMPLE_PUBKEY);
        assert_eq!(parse_pubkey(&bs58_str).unwrap(), SAMPLE_PUBKEY);
    }

    #[test]
    fn test_parse_client_token() {
        // Valid token
        assert_eq!(
            parse_client_token("secret_token_123").unwrap(),
            "secret_token_123"
        );
        // Valid token with whitespace trimming
        assert_eq!(
            parse_client_token("  my-super-secret-token  \n").unwrap(),
            "my-super-secret-token"
        );

        // Exactly 8 chars (min)
        assert_eq!(parse_client_token("12345678").unwrap(), "12345678");

        // Exactly 128 chars (max)
        let token_128 = "a".repeat(128);
        assert_eq!(parse_client_token(&token_128).unwrap(), token_128);

        // Empty
        assert!(parse_client_token("").is_err());
        assert!(parse_client_token("    ").is_err());

        // Too short (7 chars)
        assert!(parse_client_token("1234567").is_err());

        // Too long (129 chars)
        let token_129 = "a".repeat(129);
        assert!(parse_client_token(&token_129).is_err());
    }
}
