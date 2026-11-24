//! Simplicity-only taproot outputs: one leaf (version `0xbe`, script = CMR) under the BIP341
//! NUMS internal key, so there is no key path. Must match the node
//! (`wharfedale-ledger-simplicity-sys::taproot`).

use elements::secp256k1_zkp::{XOnlyPublicKey, SECP256K1};
use elements::taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo};
use elements::{Script, Witness};

/// Taproot leaf version of Simplicity.
pub const LEAF_VERSION: u8 = 0xbe;

/// BIP341's "H" point: no known discrete logarithm.
pub const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a,
    0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub fn nums_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS).expect("valid point")
}

/// The leaf `(script = CMR, version = 0xbe)`.
pub fn leaf(cmr: &[u8; 32]) -> (Script, LeafVersion) {
    (Script::from(cmr.to_vec()), LeafVersion::from_u8(LEAF_VERSION).expect("valid leaf version"))
}

pub fn spend_info(cmr: &[u8; 32]) -> TaprootSpendInfo {
    let (script, ver) = leaf(cmr);
    TaprootBuilder::new()
        .add_leaf_with_ver(0, script, ver)
        .expect("single leaf")
        .finalize(SECP256K1, nums_key())
        .expect("complete tree")
}

/// `OP_1 <Q>` locking coins to the program with commitment Merkle root `cmr`.
pub fn script_pubkey(cmr: &[u8; 32]) -> Script {
    Script::new_v1_p2tr_tweaked(spend_info(cmr).output_key())
}

pub fn control_block(cmr: &[u8; 32]) -> ControlBlock {
    spend_info(cmr).control_block(&leaf(cmr)).expect("leaf is in the tree")
}

/// Witness stack of a Simplicity spend: `[witness, program, cmr, control_block]`.
pub fn spend_witness(witness: &[u8], program: &[u8], cmr: &[u8; 32]) -> Witness {
    Witness::from_slice(&[witness.to_vec(), program.to_vec(), cmr.to_vec(), control_block(cmr).serialize()])
}
