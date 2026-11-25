//! Offline SDK behaviour: keys, destinations, contracts and signature artifacts.

use elements::secp256k1_zkp::{schnorr::Signature, Message, SECP256K1};
use elements::{BlockHash, LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid};
use serde_json::json;
use wharfedale_sdk::network::{destination, fee_asset_for};
use wharfedale_sdk::wallet::explicit_output;
use wharfedale_sdk::{contract, Contract, Key};

const P2PK: &str = include_str!("../examples/contracts/p2pk.simf");
const TIMELOCK: &str = include_str!("../examples/contracts/timelock.simf");

#[test]
fn key_file_round_trip_and_addresses() {
    let dir = std::env::temp_dir().join(format!("wf-sdk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let k = Key::generate();
    std::fs::write(dir.join("k.json"), b"old").unwrap(); // an existing file is overwritten and tightened
    k.save(&dir.join("k.json")).unwrap();
    assert_eq!(Key::load(&dir.join("k.json")).unwrap(), k);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("k.json")).unwrap().permissions().mode() & 0o777, 0o600, "key files are owner-only");
    }
    assert!(k.address().to_string().starts_with("wfc1p"));
    assert!(k.explicit_address().to_string().starts_with("wf1p"));
    assert!(Key::from_secret([0; 32]).is_err());

    let (spk, blinder) = destination(&k.address().to_string()).unwrap();
    assert_eq!((spk.clone(), blinder), (k.script_pubkey(), Some(k.blinding_public_key())));
    assert_eq!(destination(&k.explicit_address().to_string()).unwrap(), (spk.clone(), None));
    assert_eq!(destination(&hex::encode(spk.as_bytes())).unwrap(), (spk, None));
    assert!(destination("not an address").is_err());
    assert!(destination("").is_err(), "an empty script is a fee output: never a destination");
}

fn spend_tx(spk: elements::Script, lock_time: u32) -> (Transaction, Vec<TxOut>) {
    let fee = fee_asset_for("t");
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::from_height(lock_time).unwrap(),
        input: vec![TxIn { previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0), sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, ..Default::default() }],
        output: vec![explicit_output(Key::from_secret([9; 32]).unwrap().script_pubkey(), fee, 9_000), TxOut::new_fee(1_000, fee)],
    };
    (tx, vec![explicit_output(spk, fee, 10_000)])
}

#[test]
fn signature_artifact_matches_the_satisfied_program() {
    let owner = Key::from_secret([1; 32]).unwrap();
    for (src, args) in [
        (P2PK, json!({ "OWNER": format!("0x{}", owner.xonly_public_key()) })),
        (TIMELOCK, json!({ "OWNER": format!("0x{}", owner.xonly_public_key()), "AFTER": "100" })),
    ] {
        let c = Contract::compile(src, &args.to_string()).unwrap();
        let artifact = c.signature_artifact().unwrap();
        assert_eq!(artifact.signatures, vec!["SIG".to_string()]);

        let (tx, prevouts) = spend_tx(c.script_pubkey(), 150);
        let genesis = BlockHash::from_byte_array([2; 32]);
        let signer = |id: &str| -> wharfedale_sdk::Result<Key> {
            assert_eq!(id, "owner");
            Ok(owner.clone())
        };
        let w = c.satisfy(&tx, 0, &prevouts, genesis, &json!({ "SIG": "sign:owner" }), &signer).unwrap();
        let stack: Vec<Vec<u8>> = w.iter().map(<[u8]>::to_vec).collect();
        // Program bytes are what a client without a compiler sends; the witness is the signature.
        assert_eq!(hex::encode(&stack[1]), artifact.program);
        assert_eq!(hex::encode(&stack[2]), artifact.cmr);
        let sighash = contract::sig_all_hash(&tx, &prevouts, 0, &c.cmr(), genesis);
        let sig = Signature::from_slice(&stack[0]).unwrap();
        SECP256K1.verify_schnorr(&sig, &Message::from_digest(sighash), &owner.xonly_public_key()).unwrap();
    }
}

#[test]
fn unsatisfied_contract_fails_before_broadcast() {
    let owner = Key::from_secret([1; 32]).unwrap();
    let c = Contract::compile(TIMELOCK, &json!({ "OWNER": format!("0x{}", owner.xonly_public_key()), "AFTER": "100" }).to_string()).unwrap();
    let (tx, prevouts) = spend_tx(c.script_pubkey(), 99);
    let signer = |_: &str| Ok(owner.clone());
    let err = c.satisfy(&tx, 0, &prevouts, BlockHash::from_byte_array([2; 32]), &json!({ "SIG": "sign:x" }), &signer).unwrap_err();
    assert!(err.to_string().contains("not satisfied"), "{err}");
    assert!(Contract::compile("fn main() { garbage }", "{}").is_err());
    assert!(Contract::compile(P2PK, "{}").is_err(), "missing argument");
}

#[test]
fn recovery_phrases() {
    // BIP86 reference vector (coin type 0): internal key of m/86'/0'/0'/0/0.
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let k = Key::from_mnemonic_path(phrase, "m/86'/0'/0'/0/0").unwrap();
    assert_eq!(k.xonly_public_key().to_string(), "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115");
    // Whitespace and case don't matter; a bad checksum or word count does.
    assert_eq!(Key::from_mnemonic(&phrase.to_uppercase().replace(' ', "  ")).unwrap(), Key::from_mnemonic(phrase).unwrap());
    assert!(Key::from_mnemonic(&phrase.replace("about", "abandon")).is_err());
    for words in [12, 24] {
        let p = wharfedale_sdk::keys::generate_mnemonic(words).unwrap();
        assert_eq!(p.split(' ').count(), words);
        Key::from_mnemonic(&p).unwrap();
    }
    assert!(wharfedale_sdk::keys::generate_mnemonic(13).is_err());
}

#[test]
fn asset_metadata_rules() {
    use wharfedale_sdk::AssetMetadata;
    let m = AssetMetadata::new("Demo Points", "DPT", 2).unwrap();
    assert_eq!(String::from_utf8(m.encode()).unwrap(), r#"{"name":"Demo Points","precision":2,"ticker":"DPT"}"#);
    assert!(m.script().is_op_return());
    assert!(AssetMetadata::new("", "DPT", 2).is_err());
    assert!(AssetMetadata::new("x", "dpt", 2).is_err());
    assert!(AssetMetadata::new("x", "TOOLONGTK", 2).is_err());
    assert!(AssetMetadata::new("x", "DPT", 9).is_err());
    assert!(AssetMetadata::new("a\nb", "DPT", 2).is_err());
    assert!(AssetMetadata::new("é".repeat(64), "DPT", 2).is_err(), "over 128 bytes");
}
