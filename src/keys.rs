//! Wallet keys: one secret gives the key-path taproot output, the blinding key and both
//! addresses.

use std::path::Path;

use elements::hashes::sha256;
use elements::schnorr::TapTweak;
use elements::secp256k1_zkp::{Keypair, PublicKey, SecretKey, XOnlyPublicKey, SECP256K1};
use elements::{Address, Script};
use rand::RngCore;
use serde_json::json;

use crate::network::ADDRESS_PARAMS;
use crate::{Error, Result};

/// BIP32 path of the wallet key under a recovery phrase: BIP86 (taproot), coin type 1.
pub const DERIVATION_PATH: &str = "m/86'/1'/0'/0/0";

/// A new BIP39 recovery phrase of `words` words (12 or 24), English word list.
pub fn generate_mnemonic(words: usize) -> Result<String> {
    let len = match words {
        12 => 16,
        24 => 32,
        _ => return Err(Error::Key("a recovery phrase has 12 or 24 words".into())),
    };
    let mut entropy = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut entropy);
    Ok(bip39::Mnemonic::from_entropy(&entropy).map_err(|e| Error::Key(e.to_string()))?.to_string())
}

/// A 32-byte secret. Key file format: `{"secret": "<64 hex>"}` (same as node keys).
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    secret: [u8; 32],
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.xonly_public_key())
    }
}

impl Key {
    pub fn from_secret(secret: [u8; 32]) -> Result<Self> {
        SecretKey::from_slice(&secret).map_err(|e| Error::Key(e.to_string()))?;
        Ok(Self { secret })
    }

    /// The key of a BIP39 recovery phrase (checksum verified, no passphrase), at
    /// [`DERIVATION_PATH`].
    pub fn from_mnemonic(phrase: &str) -> Result<Self> {
        Self::from_mnemonic_path(phrase, DERIVATION_PATH)
    }

    /// The key of a BIP39 recovery phrase at any BIP32 `path` (e.g. `m/86'/0'/0'/0/0`).
    pub fn from_mnemonic_path(phrase: &str, path: &str) -> Result<Self> {
        use elements::bitcoin::bip32::{DerivationPath, Xpriv};
        use elements::bitcoin::secp256k1::Secp256k1;
        use elements::bitcoin::NetworkKind;
        let normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, &normalized).map_err(|e| Error::Key(format!("recovery phrase: {e}")))?;
        let seed = mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::Test, &seed).map_err(|e| Error::Key(e.to_string()))?;
        let path: DerivationPath = path.parse().map_err(|e| Error::Key(format!("derivation path: {e}")))?;
        let child = master.derive_priv(&secp, &path).map_err(|e| Error::Key(e.to_string()))?;
        Self::from_secret(child.private_key.secret_bytes())
    }

    pub fn generate() -> Self {
        loop {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            if let Ok(k) = Self::from_secret(secret) {
                return k;
            }
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let hex_secret = v.get("secret").and_then(|s| s.as_str()).ok_or_else(|| Error::Key("key file has no \"secret\"".into()))?;
        let secret: [u8; 32] = hex::decode(hex_secret)
            .map_err(|e| Error::Key(e.to_string()))?
            .try_into()
            .map_err(|_| Error::Key("secret must be 32 bytes".into()))?;
        Self::from_secret(secret)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        Ok(std::fs::write(path, serde_json::to_vec_pretty(&json!({ "secret": hex::encode(self.secret) }))?)?)
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }

    /// The untweaked keypair: contract signatures (`"sign:"` witnesses) use it.
    pub fn keypair(&self) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &self.secret).expect("validated in from_secret")
    }

    /// x-only public key (untweaked): the taproot internal key, and the key contracts check.
    pub fn xonly_public_key(&self) -> XOnlyPublicKey {
        self.keypair().x_only_public_key().0
    }

    /// The keypair tweaked for a key-path spend (`Q = P + H_TapTweak/elements(P)·G`).
    pub fn tweaked_keypair(&self) -> Keypair {
        self.keypair().tap_tweak(SECP256K1, None).to_inner()
    }

    /// Key-path-only taproot output script `OP_1 <Q>`.
    pub fn script_pubkey(&self) -> Script {
        Script::new_v1_p2tr(SECP256K1, self.xonly_public_key(), None)
    }

    /// Blinding key: SHA-256("wharfedale/blinding-key" ‖ secret).
    pub fn blinding_key(&self) -> SecretKey {
        let mut data = b"wharfedale/blinding-key".to_vec();
        data.extend_from_slice(&self.secret);
        SecretKey::from_slice(&sha256::Hash::hash(&data).to_byte_array()).expect("hash is a valid key")
    }

    pub fn blinding_public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(SECP256K1, &self.blinding_key())
    }

    /// Confidential address `wfc1p…` (default for receiving).
    pub fn address(&self) -> Address {
        Address::p2tr(SECP256K1, self.xonly_public_key(), None, Some(self.blinding_public_key()), &ADDRESS_PARAMS)
    }

    /// Explicit address `wf1p…` of the same output script.
    pub fn explicit_address(&self) -> Address {
        Address::p2tr(SECP256K1, self.xonly_public_key(), None, None, &ADDRESS_PARAMS)
    }
}
