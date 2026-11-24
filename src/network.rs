//! Chain constants shared by every Wharfedale network.

use elements::hashes::sha256;
use elements::secp256k1_zkp::PublicKey;
use elements::{Address, AddressParams, AssetId, ContractHash, OutPoint, Script, Txid};

use crate::{Error, Result};

/// Address parameters: bech32m `wf1…` (explicit), blech32 `wfc1…` (confidential).
pub static ADDRESS_PARAMS: AddressParams = AddressParams {
    p2pkh_prefix: 73,
    p2sh_prefix: 87,
    blinded_prefix: 25,
    bech_hrp: elements::bitcoin::bech32::Hrp::parse_unchecked("wf"),
    blech_hrp: elements::bitcoin::bech32::Hrp::parse_unchecked("wfc"),
};

/// The fee asset of a chain: an Elements issuance from outpoint `0000…:0` with contract hash
/// SHA-256(chain_id). Also reported by the node (`getblockchaininfo.fee_asset`).
pub fn fee_asset_for(chain_id: &str) -> AssetId {
    let contract = ContractHash::from_byte_array(sha256::Hash::hash(chain_id.as_bytes()).to_byte_array());
    AssetId::new_issuance(OutPoint::new(Txid::from_byte_array([0; 32]), 0), contract)
}

/// Parses a payment destination: a `wfc1…`/`wf1…` address, or a hex output script. Returns
/// the output script and, for a confidential address, its blinding public key.
pub fn destination(to: &str) -> Result<(Script, Option<PublicKey>)> {
    if let Ok(addr) = Address::parse_with_params(to, &ADDRESS_PARAMS) {
        return Ok((addr.script_pubkey(), addr.blinding_pubkey));
    }
    let bytes = hex::decode(to).map_err(|_| Error::Destination(to.to_string()))?;
    Ok((Script::from(bytes), None))
}
