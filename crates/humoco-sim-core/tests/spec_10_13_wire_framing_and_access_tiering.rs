//! Spec 10 & 13: Wire Framing, 3-Tier Access, Token Bucket (INV-1001,1301,1302)
use humoco_sim_core::wire::{
    AccessControl, AccessTier, LockEntry144, MsgType, TokenBucket, WireHeader, parse_wire_header,
    WIRE_MAGIC, CURRENT_PROTOCOL_VERSION, FLAG_FINAL, FLAG_PROVISIONAL,
};

// INV-1001: 144-Byte Binary Layout #[repr(C)] Zero-Copy & 32B WireHeader
#[test]
fn test_inv1001_144_byte_binary_layout_and_32b_wireheader() {
    // Size & alignment
    assert_eq!(std::mem::size_of::<LockEntry144>(), 144, "LockEntry must be 144 bytes");
    assert_eq!(LockEntry144::SIZE, 144);
    assert_eq!(std::mem::align_of::<LockEntry144>(), 8);

    assert_eq!(std::mem::size_of::<WireHeader>(), 32, "WireHeader must be 32 bytes");
    assert_eq!(WireHeader::SIZE, 32);
    assert_eq!(std::mem::align_of::<WireHeader>(), 8);

    // Zero-copy roundtrip
    let entry = LockEntry144 {
        parent_lock: [0xAA;32],
        receiver_pub: [0xBB;32],
        valid_until: 1_234_567,
        owner_signature: [0xCC;64],
        status: 1,
        padding: [0;7],
    };
    let bytes = entry.to_bytes();
    assert_eq!(bytes.len(), 144);
    let decoded = LockEntry144::from_bytes(&bytes);
    assert_eq!(entry, decoded, "zero-copy roundtrip must be bit-identical");

    let header = WireHeader::new(MsgType::LockVerifyRequest as u16, 42, 7, FLAG_FINAL, 144);
    assert!(header.is_valid_magic());
    assert_eq!(header.magic, WIRE_MAGIC);
    assert_eq!(header.protocol_version, CURRENT_PROTOCOL_VERSION);
    let raw = header.to_bytes();
    assert_eq!(raw.len(), 32);
    assert_eq!(&raw[0..4], b"HUMO");
    let decoded_h = WireHeader::from_bytes(&raw);
    assert_eq!(header, decoded_h);

    // Wire framing validation
    let ok = parse_wire_header(&raw, 42, false).expect("valid header");
    assert_eq!(ok.session_seq, 42);
    // Wrong magic
    let mut bad = raw;
    bad[0] = 0xFF;
    assert!(matches!(parse_wire_header(&bad, 42, false), Err(humoco_sim_core::wire::WireError::InvalidMagic)));
    // Wrong seq
    assert!(matches!(parse_wire_header(&raw, 43, false), Err(humoco_sim_core::wire::WireError::SequenceGap{..})));
    // 0-RTT forbidden for writes
    let write_hdr = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 1, FLAG_FINAL, 100).to_bytes();
    assert!(matches!(parse_wire_header(&write_hdr, 1, true), Err(humoco_sim_core::wire::WireError::ZeroRttForbiddenForWrites)));
    // 0-RTT allowed for reads
    let read_hdr = WireHeader::new(MsgType::StatusQuery as u16, 2, 1, 0, 0).to_bytes();
    assert_eq!(parse_wire_header(&read_hdr, 2, true).unwrap().msg_type, MsgType::StatusQuery as u16);
    let active_sync = WireHeader::new(MsgType::ActiveSyncRequest as u16, 3, 1, 0, 0).to_bytes();
    assert_eq!(parse_wire_header(&active_sync, 3, true).unwrap().msg_type, MsgType::ActiveSyncRequest as u16);
}

// INV-1301: 3-Tier Access Control (Tier1 VIP, Tier2 F2F Friend, Tier3 Light/Public mit Argon2id/PoW)
#[test]
fn test_inv1301_three_tier_access_control() {
    let secret = [0x42;32];
    let mut ac = AccessControl::new(secret);

    let vip_pub = [0x11;32];
    let friend_pub = [0x22;32];
    let _stranger_pub = [0x33;32];

    let vip_tag = ac.register_pubkey(vip_pub, AccessTier::VipMerchant);
    let friend_tag = ac.register_pubkey(friend_pub, AccessTier::FriendCommunity);
    // stranger not registered

    // Tier 1 VIP has no PoW, instant
    assert_eq!(ac.classify(Some(vip_tag)), AccessTier::VipMerchant);
    // Tier 2 Friend has no PoW
    assert_eq!(ac.classify(Some(friend_tag)), AccessTier::FriendCommunity);
    // Tier 3 Public / Light (anonymous)
    assert_eq!(ac.classify(None), AccessTier::LightPublic);
    assert_eq!(ac.classify(Some([0xFF;32])), AccessTier::LightPublic);

    // Argon2id PoW for Tier3: stateless challenge (INV-1303)
    let ip_prefix = b"192.168.1.0/24";
    let challenge = AccessControl::pow_challenge(ip_prefix, 12345, 8, &secret);
    assert_eq!(challenge.len(), 32);
    // difficulty 0: always pass
    assert!(AccessControl::verify_pow(&challenge, 0, 0));
    // difficulty 8: need leading zero byte (1 byte = 8 bits)
    let mut found = false;
    for nonce in 0..5000 {
        if AccessControl::verify_pow(&challenge, nonce, 8) {
            found = true;
            break;
        }
    }
    assert!(found, "PoW with difficulty 8 must be solvable within 5000 nonces (approx 1/256)");

    // Higher difficulty harder
    let mut count_medium = 0;
    for nonce in 0..1000 {
        if AccessControl::verify_pow(&challenge, nonce, 4) {
            count_medium += 1;
        }
    }
    let mut count_high = 0;
    for nonce in 0..1000 {
        if AccessControl::verify_pow(&challenge, nonce, 12) {
            count_high += 1;
        }
    }
    assert!(count_medium > count_high, "higher difficulty must have lower pass rate");

    // Stateless: same challenge verifies same nonce deterministically
    let nonce = 123;
    let r1 = AccessControl::verify_pow(&challenge, nonce, 4);
    let r2 = AccessControl::verify_pow(&challenge, nonce, 4);
    assert_eq!(r1, r2);

    // VIP isolation: even under Tier3 flood, VIP still <50ms (conceptual: classify is O(1))
    let start = std::time::Instant::now();
    for _ in 0..10_000 {
        let _ = ac.classify(Some(vip_tag));
    }
    assert!(start.elapsed().as_millis() < 100, "VIP classify must be fast and O(1)");
}

// INV-1302: Ingress Token-Bucket Rate Limiter
#[test]
fn test_inv1302_ingress_token_bucket_rate_limiter() {
    // 10 tokens burst, refill 10 per second
    let mut bucket = TokenBucket::new(10, 10, 0);

    // Burst consume
    for _ in 0..10 {
        assert!(bucket.try_consume(1, 0), "burst should allow 10");
    }
    assert!(!bucket.try_consume(1, 0), "exhausted must reject");

    // Refill after 500ms -> 5 tokens
    assert!(!bucket.try_consume(6, 500), "only 5 tokens after 500ms");
    assert!(bucket.try_consume(5, 500));
    assert!(!bucket.try_consume(1, 500));

    // After 1s from last refill (now 1500ms?), refill 10 tokens but cap 10
    assert!(bucket.try_consume(10, 1500));
    assert_eq!(bucket.available(1500), 0);

    // Simulate VIP vs Public tiers: VIP higher quota
    let mut vip_bucket = TokenBucket::new(100, 100, 0);
    let mut public_bucket = TokenBucket::new(10, 5, 0);
    // Both consume 10 at t=0
    assert!(vip_bucket.try_consume(10, 0));
    assert!(public_bucket.try_consume(10, 0));
    // Public exhausted, VIP still has 90
    assert!(vip_bucket.try_consume(50, 0));
    assert!(!public_bucket.try_consume(1, 0));
    // After 1s public refills 5, vip 100
    assert!(public_bucket.try_consume(5, 1000));
    assert!(!public_bucket.try_consume(1, 1000));
    assert!(vip_bucket.try_consume(100, 1000));
}

// Additional wire header flags & size invariants
#[test]
fn test_wire_header_flags_and_reserved() {
    let hdr = WireHeader::new(MsgType::StatusQuery as u16, 0, 0, FLAG_PROVISIONAL | FLAG_FINAL, 0);
    assert_eq!(hdr.flags & FLAG_PROVISIONAL, FLAG_PROVISIONAL);
    assert_eq!(hdr.flags & FLAG_FINAL, FLAG_FINAL);
    assert_eq!(hdr.reserved, 0);
    // Roundtrip preserves flags
    let bytes = hdr.to_bytes();
    let decoded = WireHeader::from_bytes(&bytes);
    assert_eq!(decoded.flags, hdr.flags);
}
