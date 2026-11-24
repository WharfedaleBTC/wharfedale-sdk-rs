//! Cross-SDK test vectors (`tests/vectors.json`): keys and addresses, fee assets, contract
//! outputs, and Simplicity `sig_all_hash` over varied transactions. The TypeScript SDK asserts
//! the same file. Regenerate with `UPDATE_VECTORS=1 cargo test --test vectors`.

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::serialize;
use elements::secp256k1_zkp::{PublicKey, SecretKey, SECP256K1};
use elements::{
    AssetBlindingNonce, AssetEntropy, AssetId, AssetIssuance, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction,
    TxIn, TxInWitness, TxOut, TxOutWitness, Txid, Witness,
};
use serde_json::{json, Value as Json};
use wharfedale_sdk::network::{fee_asset_for, ADDRESS_PARAMS};
use wharfedale_sdk::{contract, taproot, Contract, Key};

const P2PK: &str = include_str!("../examples/contracts/p2pk.simf");
const TIMELOCK: &str = include_str!("../examples/contracts/timelock.simf");

fn key(b: u8) -> Key {
    Key::from_secret([b; 32]).unwrap()
}

fn asset(b: u8) -> AssetId {
    AssetId::from_byte_array([b; 32])
}

fn explicit(spk: Script, a: AssetId, v: u64) -> TxOut {
    TxOut { asset: Asset::Explicit(a), value: Value::Explicit(v), nonce: Nonce::Null, script_pubkey: spk, witness: TxOutWitness::empty() }
}

fn input(n: u8, vout: u32) -> TxIn {
    TxIn { previous_output: OutPoint::new(Txid::from_byte_array([n; 32]), vout), sequence: Sequence::MAX, ..Default::default() }
}

/// A blinded transaction paying `n` confidential outputs to `spk` (real proofs, valid points).
fn blinded_outputs(spk: &Script, n: usize, seed: u8) -> Vec<TxOut> {
    use rand::SeedableRng;
    let blinder = PublicKey::from_secret_key(SECP256K1, &SecretKey::from_slice(&[seed; 32]).unwrap());
    let mut outputs: Vec<TxOut> = (0..n)
        .map(|i| TxOut { nonce: Nonce::Confidential(blinder), ..explicit(spk.clone(), asset(7), 1_000 + i as u64) })
        .collect();
    outputs.push(TxOut::new_fee(100, asset(7)));
    let mut tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: vec![input(seed, 0)], output: outputs };
    let total = 100 + (0..n as u64).map(|i| 1_000 + i).sum::<u64>();
    let secrets = elements::TxOutSecrets::new(asset(7), AssetBlindingFactor::zero(), total, ValueBlindingFactor::zero());
    tx.blind(&mut rand::rngs::StdRng::seed_from_u64(seed as u64), SECP256K1, &[secrets], false).unwrap();
    tx.output.truncate(n);
    tx.output
}

fn sighash_cases() -> Vec<(String, Transaction, Vec<TxOut>, u32)> {
    let c = Contract::compile(P2PK, &format!(r#"{{"OWNER": "0x{}"}}"#, key(1).xonly_public_key())).unwrap();
    let cspk = c.script_pubkey();
    let to = key(2).script_pubkey();
    let fee_asset = asset(7);
    let mut cases = Vec::new();

    // 1. Explicit spend of a contract output.
    let tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: vec![input(1, 0)], output: vec![explicit(to.clone(), fee_asset, 9_000), TxOut::new_fee(1_000, fee_asset)] };
    cases.push(("explicit".into(), tx, vec![explicit(cspk.clone(), fee_asset, 10_000)], 0));

    // 2. Two inputs (one confidential prevout), confidential outputs, input 1 signed.
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::from_height(42).unwrap(),
        input: vec![input(2, 3), TxIn { sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, ..input(3, 1) }],
        output: {
            let mut o = blinded_outputs(&to, 2, 5);
            o.push(TxOut::new_fee(500, fee_asset));
            o
        },
    };
    let conf_prevout = blinded_outputs(&key(3).script_pubkey(), 1, 8).remove(0);
    cases.push(("confidential".into(), tx, vec![conf_prevout, explicit(cspk.clone(), fee_asset, 7_000)], 1));

    // 3. New issuance on input 0 (explicit amount and tokens), contract hash non-zero.
    let mut tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: vec![input(4, 0)], output: vec![explicit(to.clone(), fee_asset, 1), TxOut::new_fee(999, fee_asset)] };
    tx.input[0].asset_issuance = AssetIssuance {
        asset_blinding_nonce: AssetBlindingNonce::NEW_ISSUANCE,
        asset_entropy: AssetEntropy::from_byte_array([0x33; 32]),
        amount: Value::Explicit(5_000),
        inflation_keys: Value::Explicit(2),
    };
    cases.push(("new_issuance".into(), tx, vec![explicit(cspk.clone(), fee_asset, 1_000)], 0));

    // 4. Reissuance with a confidential amount and its rangeproof.
    let mut tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: vec![input(5, 2)], output: vec![explicit(to.clone(), fee_asset, 1), TxOut::new_fee(999, fee_asset)] };
    let conf = blinded_outputs(&to, 1, 20).remove(0);
    tx.input[0].asset_issuance = AssetIssuance {
        asset_blinding_nonce: AssetBlindingNonce::from_byte_array([0x44; 32]),
        asset_entropy: AssetEntropy::from_byte_array([0x55; 32]),
        amount: conf.value,
        inflation_keys: Value::Null,
    };
    tx.input[0].witness = TxInWitness { amount_rangeproof: conf.witness.rangeproof.clone(), ..Default::default() };
    cases.push(("reissuance".into(), tx, vec![explicit(cspk.clone(), fee_asset, 1_000)], 0));

    // 5. Annex on the signed input, OP_RETURN with pushes, fees in two assets, non-final sequence.
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(1_800_000_000),
        input: vec![TxIn { sequence: Sequence(0xfffffffd), ..input(6, 0) }, input(7, 5)],
        output: vec![
            explicit(Script::from(vec![0x6a, 0x03, 1, 2, 3, 0x51, 0x4c, 0x02, 9, 9]), asset(9), 0),
            TxOut::new_fee(300, asset(9)),
            TxOut::new_fee(700, fee_asset),
            TxOut::new_fee(100, asset(1)),
        ],
    };
    tx.input[0].witness.script_witness = Witness::from_slice(&[vec![0xaa], vec![0x50, 1, 2, 3]]);
    cases.push(("annex_opreturn_fees".into(), tx, vec![explicit(cspk.clone(), fee_asset, 1_000), explicit(key(4).script_pubkey(), asset(9), 300)], 0));
    cases
}

fn generate() -> Json {
    let keys: Vec<Json> = [1u8, 2, 0xa1, 0xb0]
        .iter()
        .map(|b| {
            let k = key(*b);
            json!({
                "secret": hex::encode(k.secret_bytes()),
                "xonly_public_key": k.xonly_public_key().to_string(),
                "script_pubkey": hex::encode(k.script_pubkey().as_bytes()),
                "blinding_key": hex::encode(k.blinding_key().secret_bytes()),
                "blinding_public_key": k.blinding_public_key().to_string(),
                "address": k.address().to_string(),
                "explicit_address": k.explicit_address().to_string(),
            })
        })
        .collect();
    let fee_assets: Vec<Json> = ["wharfedale-docker", "m4-test", "wharfedale-local"]
        .iter()
        .map(|id| json!({ "chain_id": id, "fee_asset": fee_asset_for(id).to_string() }))
        .collect();
    let p2pk = Contract::compile(P2PK, &format!(r#"{{"OWNER": "0x{}"}}"#, key(1).xonly_public_key())).unwrap();
    let tl = Contract::compile(TIMELOCK, &format!(r#"{{"OWNER": "0x{}", "AFTER": "5"}}"#, key(2).xonly_public_key())).unwrap();
    let contracts: Vec<Json> = [("p2pk", &p2pk), ("timelock", &tl)]
        .iter()
        .map(|(name, c)| {
            json!({
                "name": name,
                "cmr": hex::encode(c.cmr()),
                "script_pubkey": hex::encode(c.script_pubkey().as_bytes()),
                "address": c.address().to_string(),
                "control_block": hex::encode(taproot::control_block(&c.cmr()).serialize()),
                "artifact": c.signature_artifact().unwrap(),
            })
        })
        .collect();
    let genesis = BlockHash::from_byte_array([0x11; 32]);
    let sighashes: Vec<Json> = sighash_cases()
        .into_iter()
        .map(|(name, tx, prevouts, ix)| {
            json!({
                "name": name,
                "tx": hex::encode(serialize(&tx)),
                "prevouts": prevouts.iter().map(|p| hex::encode(serialize(p))).collect::<Vec<_>>(),
                "ix": ix,
                "cmr": hex::encode(p2pk.cmr()),
                "genesis_hash": genesis.to_string(),
                "sig_all_hash": hex::encode(contract::sig_all_hash(&tx, &prevouts, ix, &p2pk.cmr(), genesis)),
            })
        })
        .collect();
    let mnemonics: Vec<Json> = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "cabin orbit velvet tunnel maple silent harvest copper ladder glance rescue dwarf",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    ]
    .iter()
    .filter_map(|p| Key::from_mnemonic(p).ok().map(|k| (p, k)))
    .map(|(p, k)| {
        json!({
            "phrase": p,
            "path": wharfedale_sdk::keys::DERIVATION_PATH,
            "secret": hex::encode(k.secret_bytes()),
            "xonly_public_key": k.xonly_public_key().to_string(),
            "address": k.address().to_string(),
        })
    })
    .collect();
    let metadata: Vec<Json> = [("Demo Points", "DPT", 2u8), ("Harbour Tickets", "HBT", 0), ("Grüße ✓", "GR8", 8)]
        .iter()
        .map(|(n, t, p)| {
            let m = wharfedale_sdk::AssetMetadata::new(*n, *t, *p).unwrap();
            let prevout = OutPoint::new(Txid::from_byte_array([5; 32]), 1);
            let contract = elements::ContractHash::from_byte_array(m.contract_hash());
            let entropy = AssetId::generate_asset_entropy(prevout, contract);
            json!({
                "metadata": String::from_utf8(m.encode()).unwrap(),
                "contract_hash": hex::encode(m.contract_hash()),
                "script": hex::encode(m.script().as_bytes()),
                "prevout_txid": prevout.txid.to_string(),
                "prevout_vout": prevout.vout,
                "asset": AssetId::from_entropy(entropy).to_string(),
                "token": AssetId::reissuance_token_from_entropy(entropy, false).to_string(),
            })
        })
        .collect();
    json!({
        "mnemonics": mnemonics,
        "metadata": metadata,
        "address_params": { "bech_hrp": ADDRESS_PARAMS.bech_hrp.to_string(), "blech_hrp": ADDRESS_PARAMS.blech_hrp.to_string() },
        "keys": keys,
        "fee_assets": fee_assets,
        "contracts": contracts,
        "sig_all_hash": sighashes,
    })
}

#[test]
fn vectors_are_current() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json");
    let fresh = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        std::fs::write(path, &fresh).unwrap();
    }
    let stored = std::fs::read_to_string(path).expect("run with UPDATE_VECTORS=1 to create tests/vectors.json");
    assert_eq!(stored, fresh, "vectors changed: review, then regenerate with UPDATE_VECTORS=1");
}
