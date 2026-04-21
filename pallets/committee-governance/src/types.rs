//! Types for `pallet_committee_governance`. Mirrors the RotationSchedule and
//! LastMirrorTx structs in `docs/spec-v1.md §3.1`.

use codec::{Decode, Encode, MaxEncodedLen};
use parity_scale_codec as codec;
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

pub type CommitteePubkey = [u8; 32];
pub type BlockNumber = u32;

pub const TAG_CMTT: &[u8; 4] = b"CMTT";

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
pub enum CommitteeEvent {
    Added { pubkey: CommitteePubkey },
    Removed { pubkey: CommitteePubkey },
    RotatedPubkey { old: CommitteePubkey, new: CommitteePubkey },
    ExpandedThreshold { old: u32, new: u32 },
}

#[derive(Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq, Default)]
pub struct LastMirrorTx {
    pub committee_set_digest: [u8; 32],
    pub cardano_tx_hash: [u8; 32],
    pub mirrored_at_block: BlockNumber,
}

/// `blake2_256(tag || body)`.
pub fn domain_hash(tag: [u8; 4], body: &[u8]) -> [u8; 32] {
    let mut buf = sp_std::vec::Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(body);
    sp_core::hashing::blake2_256(&buf)
}

/// `blake2_256(b"CMTT" || scale(Vec<[u8;32]>) || threshold (LE32))`.
pub fn compute_committee_set_digest(pubkeys: &[CommitteePubkey], threshold: u32) -> [u8; 32] {
    let mut body = sp_std::vec::Vec::new();
    body.extend_from_slice(&pubkeys.to_vec().encode());
    body.extend_from_slice(&threshold.to_le_bytes());
    domain_hash(*TAG_CMTT, &body)
}
