//! SimplicityHL contracts: compile a program with its arguments, lock coins to it, spend them.
//!
//! Witness values are SimplicityHL witness JSON (`{"NAME": "value"}`, values as strings). A
//! string value `"sign:<id>"` is replaced, per input, by the BIP340 signature over that input's
//! `sig_all_hash` of the key `signer(id)` returns (untweaked, see [`Key::keypair`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use elements::secp256k1_zkp::{Message, SECP256K1};
use elements::{Address, AssetId, BlockHash, LockTime, Script, Sequence, Transaction, TxOut, Txid, Witness};
use serde_json::{Map, Value};
use simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicity::Cmr;
use simplicityhl::{ast::ElementsJetHinter, CompiledProgram, TemplateAst, UnresolvedValues};

use crate::client::Client;
use crate::keys::Key;
use crate::network::{destination, ADDRESS_PARAMS};
use crate::taproot;
use crate::wallet::{blind, coins_at, need_more, output_to, select, unsigned_tx, Coin, DEFAULT_FEE};
use crate::{Error, Result};

/// A compiled SimplicityHL program.
pub struct Contract {
    program: CompiledProgram,
    cmr: [u8; 32],
}

/// Simplicity's `sig_all_hash` for input `ix`: what `jet::sig_all_hash()` returns when the
/// program runs, and what contract signatures sign. `prevouts[i]` is the output spent by
/// input `i`; the program is identified by `cmr` (single-leaf control block).
pub fn sig_all_hash(tx: &Transaction, prevouts: &[TxOut], ix: u32, cmr: &[u8; 32], genesis: BlockHash) -> [u8; 32] {
    env(tx, prevouts, ix, cmr, genesis).c_tx_env().sighash_all().to_byte_array()
}

fn env(tx: &Transaction, prevouts: &[TxOut], ix: u32, cmr: &[u8; 32], genesis: BlockHash) -> ElementsEnv<Arc<Transaction>> {
    ElementsEnv::new(
        Arc::new(tx.clone()),
        prevouts.iter().cloned().map(ElementsUtxo::from).collect(),
        ix,
        Cmr::from_byte_array(*cmr),
        taproot::control_block(cmr),
        None,
        genesis,
    )
}

impl Contract {
    /// Compiles SimplicityHL `source` with arguments `args` (JSON object of `param::` values).
    pub fn compile(source: &str, args: &str) -> Result<Self> {
        let tmpl = TemplateAst::new(source, Box::new(ElementsJetHinter::new())).map_err(|e| Error::Contract(e.to_string()))?;
        let args = serde_json::from_str::<UnresolvedValues>(args)
            .map_err(|e| Error::Contract(format!("arguments: {e}")))?
            .resolve(tmpl.parameters())
            .map_err(|e| Error::Contract(format!("arguments: {e}")))?;
        let program = tmpl.instantiate(args, false).map_err(|e| Error::Contract(e.to_string()))?;
        let cmr = program.commit().cmr().to_byte_array();
        Ok(Self { program, cmr })
    }

    /// Commitment Merkle root: identifies the program (and its arguments).
    pub fn cmr(&self) -> [u8; 32] {
        self.cmr
    }

    pub fn script_pubkey(&self) -> Script {
        taproot::script_pubkey(&self.cmr)
    }

    /// Explicit address `wf1p…` (contract outputs are not blinded).
    pub fn address(&self) -> Address {
        Address::from_script(&self.script_pubkey(), None, &ADDRESS_PARAMS).expect("taproot script")
    }

    /// Names of the program's `witness::` values.
    pub fn witness_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.program.witness_types().as_ref().keys().map(|k| k.to_string()).collect();
        names.sort();
        names
    }

    /// The witness stack spending input `ix` of `tx`. Runs (and prunes) the program against
    /// the transaction: a witness that does not satisfy it fails here, before broadcasting.
    pub fn satisfy(
        &self,
        tx: &Transaction,
        ix: u32,
        prevouts: &[TxOut],
        genesis: BlockHash,
        witness: &Value,
        signer: &dyn Fn(&str) -> Result<Key>,
    ) -> Result<Witness> {
        let env = env(tx, prevouts, ix, &self.cmr, genesis);
        let sighash = env.c_tx_env().sighash_all().to_byte_array();
        let filled = fill_signatures(witness, &sighash, signer)?;
        let values = serde_json::from_value::<UnresolvedValues>(filled)
            .map_err(|e| Error::Contract(format!("witness: {e}")))?
            .resolve(self.program.witness_types())
            .map_err(|e| Error::Contract(format!("witness: {e}")))?;
        let satisfied = self.program.satisfy_with_env(values, Some(&env)).map_err(|e| Error::Contract(format!("not satisfied: {e}")))?;
        let (program, witness) = satisfied.redeem().to_vec_with_witness();
        Ok(taproot::spend_witness(&witness, &program, &self.cmr))
    }

    /// For programs whose witness is only 64-byte signatures and that have no branches
    /// (e.g. p2pk, timelock + signature): the program bytes and the witness names in the order
    /// their signatures are concatenated into the witness bytes. Lets clients without a
    /// SimplicityHL compiler (the TypeScript SDK) spend: witness = sig₁ ‖ sig₂ ‖ …
    pub fn signature_artifact(&self) -> Result<SignatureArtifact> {
        let names = self.witness_names();
        // Distinct marker per name (byte i+1 repeated) reveals each signature's position.
        let mut values = Map::new();
        for (i, name) in names.iter().enumerate() {
            values.insert(name.clone(), Value::String(format!("0x{}", hex::encode([(i + 1) as u8; 64]))));
        }
        let values = serde_json::from_value::<UnresolvedValues>(Value::Object(values))
            .map_err(|e| Error::Contract(e.to_string()))?
            .resolve(self.program.witness_types())
            .map_err(|e| Error::Contract(format!("only Signature witnesses are supported: {e}")))?;
        let satisfied = self.program.satisfy(values).map_err(|e| Error::Contract(e.to_string()))?;
        let (program, witness) = satisfied.redeem().to_vec_with_witness();
        if witness.len() != 64 * names.len() {
            return Err(Error::Contract("witness is not a concatenation of signatures".into()));
        }
        let mut order = Vec::new();
        for chunk in witness.chunks(64) {
            let i = chunk[0] as usize;
            if i == 0 || i > names.len() || chunk.iter().any(|b| *b != chunk[0]) {
                return Err(Error::Contract("witness is not a concatenation of signatures".into()));
            }
            order.push(names[i - 1].clone());
        }
        Ok(SignatureArtifact { cmr: hex::encode(self.cmr), program: hex::encode(program), signatures: order })
    }
}

/// A precompiled signature-only contract (see [`Contract::signature_artifact`]).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SignatureArtifact {
    pub cmr: String,
    pub program: String,
    /// Witness names in witness order.
    pub signatures: Vec<String>,
}

fn fill_signatures(v: &Value, sighash: &[u8; 32], signer: &dyn Fn(&str) -> Result<Key>) -> Result<Value> {
    Ok(match v {
        Value::String(s) if s.starts_with("sign:") => {
            let key = signer(&s["sign:".len()..])?;
            let sig = SECP256K1.sign_schnorr(&Message::from_digest(*sighash), &key.keypair());
            Value::String(format!("0x{}", hex::encode(sig.serialize())))
        }
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| Ok((k.clone(), fill_signatures(v, sighash, signer)?))).collect::<Result<_>>()?),
        Value::Array(a) => Value::Array(a.iter().map(|v| fill_signatures(v, sighash, signer)).collect::<Result<_>>()?),
        other => other.clone(),
    })
}

/// Explicit coins locked to the contract.
pub fn coins(client: &Client, c: &Contract) -> Result<Vec<Coin>> {
    coins_at(client, &c.script_pubkey(), None)
}

/// A spend of contract coins.
#[derive(Clone, Debug)]
pub struct ContractSpend {
    pub to: String,
    pub amount: u64,
    /// Default: the fee asset.
    pub asset: Option<AssetId>,
    pub fee: u64,
    /// Transaction lock time, for contracts that check it: a block height below 500 000 000, a
    /// unix time (compared with the block's timestamp) at or above.
    pub lock_time: Option<u32>,
    /// Witness JSON (`"sign:<id>"` placeholders allowed).
    pub witness: Value,
}

impl ContractSpend {
    pub fn new(to: impl Into<String>, amount: u64, witness: Value) -> Self {
        Self { to: to.into(), amount, asset: None, fee: DEFAULT_FEE, lock_time: None, witness }
    }
}

/// Builds a spend of contract coins: `amount` to `to`, the fee from contract coins too, change
/// back to the contract. Not broadcast.
pub fn build_spend(client: &Client, c: &Contract, spend: &ContractSpend, signer: &dyn Fn(&str) -> Result<Key>) -> Result<Transaction> {
    let info = client.chain_info()?;
    let asset = spend.asset.unwrap_or(info.fee_asset);
    let (dest, dest_blinder) = destination(&spend.to)?;
    let me = c.script_pubkey();

    let mut need = BTreeMap::new();
    need_more(&mut need, asset, spend.amount)?;
    need_more(&mut need, info.fee_asset, spend.fee)?;
    let mut pool = coins(client, c)?;
    let mut inputs = Vec::new();
    let mut outputs = vec![output_to(dest, asset, spend.amount, dest_blinder)];
    for (a, needed) in need {
        let (taken, total) = select(&mut pool, a, needed)?;
        inputs.extend(taken);
        if total > needed {
            outputs.push(output_to(me.clone(), a, total - needed, None));
        }
    }
    outputs.push(TxOut::new_fee(spend.fee, info.fee_asset));

    let mut tx = unsigned_tx(&inputs, outputs);
    if let Some(lock) = spend.lock_time {
        tx.lock_time = LockTime::from_consensus(lock);
        for i in &mut tx.input {
            i.sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
        }
    }
    let domain: Vec<_> = inputs.iter().map(|c| c.secrets).collect();
    blind(&mut tx, &domain)?;
    let prevouts: Vec<TxOut> = inputs.iter().map(|c| c.txout.clone()).collect();
    for ix in 0..tx.input.len() {
        let w = c.satisfy(&tx, ix as u32, &prevouts, info.genesis_hash, &spend.witness, signer)?;
        tx.input[ix].witness.script_witness = w;
    }
    Ok(tx)
}

pub fn spend(client: &Client, c: &Contract, spend: &ContractSpend, signer: &dyn Fn(&str) -> Result<Key>) -> Result<Txid> {
    client.send_transaction(&build_spend(client, c, spend, signer)?)
}
