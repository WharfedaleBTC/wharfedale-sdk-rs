//! On-chain asset names (Wharfedale convention, not consensus): an issuance transaction carries
//! `OP_RETURN <"WFA1"> <metadata>` and its new-issuance contract hash is SHA-256(metadata), so
//! the asset id (derived from the contract hash) commits to its name. Nodes verify and index it
//! (`/asset/:id` → `name`, `ticker`, `precision`).

use elements::hashes::sha256;
use elements::opcodes::all::OP_RETURN;
use elements::script::Builder;
use elements::Script;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Prefix push of the metadata output.
pub const TAG: &[u8; 4] = b"WFA1";
/// Largest metadata, in bytes.
pub const MAX_LEN: usize = 128;

/// Name, ticker and decimal places of an asset. Serialized canonically (fields in this order,
/// no whitespace): `{"name":…,"precision":…,"ticker":…}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetMetadata {
    pub name: String,
    pub precision: u8,
    pub ticker: String,
}

impl AssetMetadata {
    pub fn new(name: impl Into<String>, ticker: impl Into<String>, precision: u8) -> Result<Self> {
        let m = Self { name: name.into().trim().to_string(), precision, ticker: ticker.into() };
        m.validate()?;
        Ok(m)
    }

    /// Same rules as the node's indexer: name 1–64 characters without control characters,
    /// ticker `[A-Z0-9]{1,8}`, precision 0–8, encoding at most 128 bytes.
    pub fn validate(&self) -> Result<()> {
        let n = self.name.trim().chars().count();
        if n == 0 || n > 64 || self.name.chars().any(char::is_control) {
            return Err(Error::Transaction("asset name must be 1–64 characters".into()));
        }
        if self.ticker.is_empty() || self.ticker.len() > 8 || !self.ticker.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
            return Err(Error::Transaction("ticker must be 1–8 characters A–Z or 0–9".into()));
        }
        if self.precision > 8 {
            return Err(Error::Transaction("precision must be 0–8".into()));
        }
        if self.encode().len() > MAX_LEN {
            return Err(Error::Transaction(format!("metadata exceeds {MAX_LEN} bytes")));
        }
        Ok(())
    }

    /// The canonical JSON bytes.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializable")
    }

    /// The issuance contract hash: SHA-256 of [`encode`](Self::encode).
    pub fn contract_hash(&self) -> [u8; 32] {
        sha256::Hash::hash(&self.encode()).to_byte_array()
    }

    /// `OP_RETURN <"WFA1"> <metadata>`.
    pub fn script(&self) -> Script {
        Builder::new().push_opcode(OP_RETURN).push_slice(TAG).push_slice(&self.encode()).into_script()
    }
}
