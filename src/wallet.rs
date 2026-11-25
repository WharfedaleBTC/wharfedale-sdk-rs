//! Single-key wallet: coin discovery (unblinding), payments, issuance, reissuance.
//!
//! Every `build_*` method returns a blinded, signed transaction without broadcasting it; the
//! matching method without the prefix also sends it.

use std::collections::{BTreeMap, HashMap};

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value as ConfValue, ValueBlindingFactor};
use elements::secp256k1_zkp::{Message, PublicKey, SecretKey, SECP256K1};
use elements::sighash::{Prevouts, SighashCache};
use elements::{
    AssetBlindingNonce, AssetEntropy, AssetId, AssetIssuance, BlockHash, LockTime, OutPoint, SchnorrSighashType, Script,
    Sequence, Transaction, TxIn, TxOut, TxOutSecrets, TxOutWitness, Txid, Witness,
};

use crate::client::{ChainInfo, Client};
use crate::keys::Key;
use crate::metadata::AssetMetadata;
use crate::network::destination;
use crate::{Error, Result};

/// Default fee in fee-asset units: 100 (100 sats when the fee asset is bitcoin-like). Clears the
/// node's default minimum relay rate (10 units per 1 000 vbytes) for transactions up to
/// 10 000 vbytes; a confidential payment is about 1 500–2 500, an issuance about 3 900.
pub const DEFAULT_FEE: u64 = 100;

/// A spendable output with its opening (asset, value and blinding factors).
#[derive(Clone, Debug)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub secrets: TxOutSecrets,
    pub confidential: bool,
}

impl Coin {
    pub fn asset(&self) -> AssetId {
        self.secrets.asset
    }
    pub fn value(&self) -> u64 {
        self.secrets.value
    }
}

/// Opening of an explicit output (zero blinding factors).
pub fn explicit_secrets(asset: AssetId, value: u64) -> TxOutSecrets {
    TxOutSecrets::new(asset, AssetBlindingFactor::zero(), value, ValueBlindingFactor::zero())
}

/// Confirmed coins locked to `spk` and not spent in the node's mempool. Confidential outputs
/// are unblinded with `blinding_key`; outputs it can't open (or all, without one) are skipped.
pub fn coins_at(client: &Client, spk: &Script, blinding_key: Option<SecretKey>) -> Result<Vec<Coin>> {
    let mut txs: HashMap<Txid, Transaction> = HashMap::new();
    let mut out = Vec::new();
    for u in client.script_utxos(spk)? {
        if u.spent_in_mempool {
            continue;
        }
        let tx = match txs.entry(u.txid) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => e.insert(client.transaction(&u.txid)?),
        };
        let txout = tx.output.get(u.vout as usize).ok_or_else(|| Error::Response(format!("{}:{} missing", u.txid, u.vout)))?.clone();
        let (secrets, confidential) = match (txout.asset, txout.value) {
            (Asset::Explicit(a), ConfValue::Explicit(v)) => (explicit_secrets(a, v), false),
            _ => match blinding_key.and_then(|bk| txout.unblind(SECP256K1, bk).ok()) {
                Some(s) => (s, true),
                None => continue,
            },
        };
        out.push(Coin { outpoint: OutPoint::new(u.txid, u.vout), txout, secrets, confidential });
    }
    Ok(out)
}

/// An explicit output.
pub fn explicit_output(script_pubkey: Script, asset: AssetId, value: u64) -> TxOut {
    TxOut { asset: Asset::Explicit(asset), value: ConfValue::Explicit(value), nonce: Nonce::Null, script_pubkey, witness: TxOutWitness::empty() }
}

/// An explicit output that [`blind`] blinds to `blinder` (Elements convention: the blinding
/// public key travels in the nonce until blinding).
pub fn output_to(script_pubkey: Script, asset: AssetId, value: u64, blinder: Option<PublicKey>) -> TxOut {
    let mut out = explicit_output(script_pubkey, asset, value);
    if let Some(pk) = blinder {
        out.nonce = Nonce::Confidential(pk);
    }
    out
}

/// Blinds every output marked with a blinding key. `domain`: the opening of each surjection
/// domain entry in consensus order — per input, its spent output, then its issuance
/// pseudo-inputs (asset, then token). A transaction spending confidential coins needs at
/// least one blinded output.
pub fn blind(tx: &mut Transaction, domain: &[TxOutSecrets]) -> Result<()> {
    if tx.output.iter().any(|o| o.nonce.is_confidential()) {
        tx.blind(&mut rand::thread_rng(), SECP256K1, domain, false).map_err(|e| Error::Transaction(format!("blinding: {e:?}")))?;
    }
    Ok(())
}

/// Signs every input with `key` on the key path (`SIGHASH_DEFAULT`, Elements taproot sighash
/// committing to `genesis`). `prevouts[i]` is the output spent by input `i`.
pub fn sign_key_path(tx: &mut Transaction, prevouts: &[TxOut], key: &Key, genesis: BlockHash) -> Result<()> {
    let tweaked = key.tweaked_keypair();
    for ix in 0..tx.input.len() {
        let hash = SighashCache::new(&*tx)
            .taproot_key_spend_signature_hash(ix, &Prevouts::All(prevouts), SchnorrSighashType::Default, genesis)
            .map_err(|e| Error::Transaction(format!("sighash: {e}")))?;
        let sig = SECP256K1.sign_schnorr(&Message::from_digest(hash.to_byte_array()), &tweaked);
        tx.input[ix].witness.script_witness = Witness::from_slice(&[sig.serialize()]);
    }
    Ok(())
}

/// Largest-first selection of `amount` of `asset` from `pool` (removing what it takes).
pub fn select(pool: &mut Vec<Coin>, asset: AssetId, amount: u64) -> Result<(Vec<Coin>, u64)> {
    pool.sort_by_key(|c| std::cmp::Reverse(c.value()));
    let mut taken = Vec::new();
    let mut total = 0u64;
    while total < amount {
        let Some(i) = pool.iter().position(|c| c.asset() == asset) else {
            return Err(Error::InsufficientFunds { asset, have: total, need: amount });
        };
        let c = pool.remove(i);
        total = total.checked_add(c.value()).ok_or_else(|| Error::Response("coin values overflow".into()))?;
        taken.push(c);
    }
    Ok((taken, total))
}

/// `a + b`, or an error naming what overflowed (amounts come from callers and the node).
pub(crate) fn add(a: u64, b: u64, what: &str) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| Error::Transaction(format!("{what} overflows")))
}

/// Adds `amount` of `asset` to what a transaction needs.
pub(crate) fn need_more(need: &mut BTreeMap<AssetId, u64>, asset: AssetId, amount: u64) -> Result<()> {
    let n = need.entry(asset).or_insert(0);
    *n = add(*n, amount, "amount plus fee")?;
    Ok(())
}

/// An unsigned version-2 transaction spending `inputs` (final sequences).
pub fn unsigned_tx(inputs: &[Coin], output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: inputs.iter().map(|c| TxIn { previous_output: c.outpoint, sequence: Sequence::MAX, ..Default::default() }).collect(),
        output,
    }
}

/// Payment options.
#[derive(Clone, Debug)]
pub struct SendOptions {
    /// Asset to pay; default: the chain's fee asset.
    pub asset: Option<AssetId>,
    /// Fee in fee-asset units.
    pub fee: u64,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self { asset: None, fee: DEFAULT_FEE }
    }
}

/// Result of an issuance.
#[derive(Clone, Debug)]
pub struct Issued {
    pub txid: Txid,
    pub asset: AssetId,
    /// Reissuance token (meaningful when tokens > 0).
    pub token: AssetId,
}

#[derive(Clone, Debug)]
pub struct Wallet {
    client: Client,
    key: Key,
}

impl Wallet {
    pub fn new(client: Client, key: Key) -> Self {
        Self { client, key }
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Confirmed coins of this key (confidential ones unblinded), not spent in the mempool.
    pub fn coins(&self) -> Result<Vec<Coin>> {
        coins_at(&self.client, &self.key.script_pubkey(), Some(self.key.blinding_key()))
    }

    pub fn balances(&self) -> Result<BTreeMap<AssetId, u64>> {
        let mut map = BTreeMap::new();
        for c in self.coins()? {
            *map.entry(c.asset()).or_insert(0) += c.value();
        }
        Ok(map)
    }

    /// Pays `amount` to `to` (a `wfc1`/`wf1` address or hex script). Confidential when the
    /// destination is a `wfc1` address or any selected coin is confidential; change is then
    /// blinded to this key.
    pub fn build_send(&self, to: &str, amount: u64, opts: &SendOptions) -> Result<Transaction> {
        let info = self.client.chain_info()?;
        let asset = opts.asset.unwrap_or(info.fee_asset);
        let (dest, dest_blinder) = destination(to)?;
        let me = self.key.script_pubkey();

        let mut need: BTreeMap<AssetId, u64> = BTreeMap::new();
        need_more(&mut need, asset, amount)?;
        need_more(&mut need, info.fee_asset, opts.fee)?;

        let mut pool = self.coins()?;
        let mut inputs = Vec::new();
        let mut change: Vec<(AssetId, u64)> = Vec::new();
        for (a, needed) in &need {
            let (taken, total) = select(&mut pool, *a, *needed)?;
            inputs.extend(taken);
            if total > *needed {
                change.push((*a, total - needed));
            }
        }
        let confidential = dest_blinder.is_some() || inputs.iter().any(|c| c.confidential);
        // Confidential inputs need a blinded output: with an explicit destination and exact
        // change, take one more fee-asset coin so a blinded change output exists.
        if confidential && dest_blinder.is_none() && change.is_empty() {
            let (extra, value) = select(&mut pool, info.fee_asset, 1)
                .map_err(|_| Error::Transaction("spending confidential coins to an explicit address needs change; no spare coin".into()))?;
            inputs.extend(extra);
            change.push((info.fee_asset, value));
        }
        let own_blinder = confidential.then(|| self.key.blinding_public_key());

        let mut outputs = vec![output_to(dest, asset, amount, dest_blinder)];
        for (a, v) in change {
            outputs.push(output_to(me.clone(), a, v, own_blinder));
        }
        outputs.push(TxOut::new_fee(opts.fee, info.fee_asset));
        self.finish(&info, unsigned_tx(&inputs, outputs), &inputs, &[])
    }

    pub fn send(&self, to: &str, amount: u64, opts: &SendOptions) -> Result<Txid> {
        self.client.send_transaction(&self.build_send(to, amount, opts)?)
    }

    /// Issues `amount` of a new asset and `tokens` reissuance tokens (explicit amounts), both
    /// paid confidentially to this key (the token must be confidential to be reissued).
    pub fn build_issue(&self, amount: u64, tokens: u64, fee: u64) -> Result<(Transaction, AssetId, AssetId)> {
        self.build_issue_with(amount, tokens, fee, None)
    }

    /// [`build_issue`](Self::build_issue), optionally naming the asset on chain
    /// ([`AssetMetadata`]: contract hash = SHA-256(metadata), plus an `OP_RETURN "WFA1"` output).
    pub fn build_issue_with(
        &self,
        amount: u64,
        tokens: u64,
        fee: u64,
        metadata: Option<&AssetMetadata>,
    ) -> Result<(Transaction, AssetId, AssetId)> {
        if let Some(m) = metadata {
            m.validate()?;
        }
        let info = self.client.chain_info()?;
        let me = self.key.script_pubkey();
        let own = Some(self.key.blinding_public_key());
        let mut pool = self.coins()?;
        let (inputs, total) = select(&mut pool, info.fee_asset, add(fee, 1, "fee")?)?;

        let mut tx = unsigned_tx(&inputs, vec![]);
        tx.input[0].asset_issuance = AssetIssuance {
            asset_blinding_nonce: AssetBlindingNonce::NEW_ISSUANCE,
            // New issuance: this field is the contract hash (0, or SHA-256 of the metadata).
            asset_entropy: metadata.map_or(AssetEntropy::NEW_ISSUANCE, |m| AssetEntropy::from_byte_array(m.contract_hash())),
            amount: ConfValue::Explicit(amount),
            inflation_keys: if tokens > 0 { ConfValue::Explicit(tokens) } else { ConfValue::Null },
        };
        let (asset, token) = tx.input[0].issuance_ids();
        tx.output.push(output_to(me.clone(), asset, amount, own));
        if tokens > 0 {
            tx.output.push(output_to(me.clone(), token, tokens, own));
        }
        tx.output.push(output_to(me, info.fee_asset, total - fee, own));
        if let Some(m) = metadata {
            tx.output.push(explicit_output(m.script(), info.fee_asset, 0));
        }
        tx.output.push(TxOut::new_fee(fee, info.fee_asset));

        let mut extra = vec![explicit_secrets(asset, amount)];
        if tokens > 0 {
            extra.push(explicit_secrets(token, tokens));
        }
        let tx = self.finish(&info, tx, &inputs, &[extra])?;
        Ok((tx, asset, token))
    }

    pub fn issue(&self, amount: u64, tokens: u64, fee: u64) -> Result<Issued> {
        let (tx, asset, token) = self.build_issue(amount, tokens, fee)?;
        Ok(Issued { txid: self.client.send_transaction(&tx)?, asset, token })
    }

    /// Issues an asset named on chain by `metadata`.
    pub fn issue_named(&self, amount: u64, tokens: u64, fee: u64, metadata: &AssetMetadata) -> Result<Issued> {
        let (tx, asset, token) = self.build_issue_with(amount, tokens, fee, Some(metadata))?;
        Ok(Issued { txid: self.client.send_transaction(&tx)?, asset, token })
    }

    /// Reissues `amount` more of `asset` by spending a held reissuance token (returned to this
    /// key). Reads the issuance entropy from the node's Esplora `/asset/:id`.
    pub fn build_reissue(&self, asset: AssetId, amount: u64, fee: u64) -> Result<Transaction> {
        let info = self.client.chain_info()?;
        let record = self.client.asset(&asset)?;
        let token = record.reissuance_token.ok_or_else(|| Error::Transaction(format!("{asset} has no reissuance token")))?;
        let me = self.key.script_pubkey();
        let own = Some(self.key.blinding_public_key());
        let mut pool = self.coins()?;
        let i = pool
            .iter()
            .position(|c| c.asset() == token && c.confidential)
            .ok_or_else(|| Error::Transaction(format!("no confidential reissuance token for {asset}")))?;
        let token_coin = pool.remove(i);
        let (fee_coins, total) = select(&mut pool, info.fee_asset, add(fee, 1, "fee")?)?;
        let mut inputs = vec![token_coin.clone()];
        inputs.extend(fee_coins);

        let mut tx = unsigned_tx(&inputs, vec![]);
        tx.input[0].asset_issuance = AssetIssuance {
            asset_blinding_nonce: AssetBlindingNonce::from_blinding_factor(token_coin.secrets.asset_bf),
            asset_entropy: AssetEntropy::from_byte_array(record.entropy),
            amount: ConfValue::Explicit(amount),
            inflation_keys: ConfValue::Null,
        };
        if tx.input[0].issuance_ids().0 != asset {
            return Err(Error::Transaction(format!("issuance entropy does not derive {asset}")));
        }
        tx.output = vec![
            output_to(me.clone(), asset, amount, own),
            output_to(me.clone(), token, token_coin.value(), own),
            output_to(me, info.fee_asset, total - fee, own),
            TxOut::new_fee(fee, info.fee_asset),
        ];
        self.finish(&info, tx, &inputs, &[vec![explicit_secrets(asset, amount)]])
    }

    pub fn reissue(&self, asset: AssetId, amount: u64, fee: u64) -> Result<Txid> {
        self.client.send_transaction(&self.build_reissue(asset, amount, fee)?)
    }

    /// Blinds (domain: each input's opening, then `domain_extra[i]` after input `i`) and signs.
    fn finish(&self, info: &ChainInfo, mut tx: Transaction, inputs: &[Coin], domain_extra: &[Vec<TxOutSecrets>]) -> Result<Transaction> {
        if !tx.output.iter().any(|o| o.nonce.is_confidential()) && inputs.iter().any(|c| c.confidential) {
            return Err(Error::Transaction("spending confidential coins needs at least one blinded output".into()));
        }
        let mut domain = Vec::new();
        for (i, c) in inputs.iter().enumerate() {
            domain.push(c.secrets);
            domain.extend(domain_extra.get(i).cloned().unwrap_or_default());
        }
        blind(&mut tx, &domain)?;
        let prevouts: Vec<TxOut> = inputs.iter().map(|c| c.txout.clone()).collect();
        sign_key_path(&mut tx, &prevouts, &self.key, info.genesis_hash)?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(asset: AssetId, value: u64, n: u8) -> Coin {
        let outpoint = OutPoint::new(Txid::from_byte_array([n; 32]), 0);
        Coin { outpoint, txout: explicit_output(Script::new(), asset, value), secrets: explicit_secrets(asset, value), confidential: false }
    }

    #[test]
    fn amounts_never_overflow() {
        let asset = AssetId::from_byte_array([1; 32]);
        // Node-reported values that would wrap: an error, not a wrong total.
        let mut pool = vec![coin(asset, u64::MAX, 1), coin(asset, 1, 2)];
        assert!(select(&mut pool, asset, u64::MAX).is_ok());
        let mut pool = vec![coin(asset, u64::MAX - 1, 1), coin(asset, 2, 2)];
        assert!(select(&mut pool, asset, u64::MAX).is_err());
        // Caller amounts: amount + fee in the same asset.
        let mut need = BTreeMap::new();
        need_more(&mut need, asset, u64::MAX - 10).unwrap();
        assert!(need_more(&mut need, asset, 100).is_err());
        assert!(add(u64::MAX, 1, "fee").is_err());
    }
}
