//! Against a running network (e.g. `wharfedale/docker`): set `WHARFEDALE_RPC` (node URL) and
//! `WHARFEDALE_FAUCET` (faucet key file), then `cargo test --test e2e -- --ignored`.

use std::time::Duration;

use serde_json::json;
use wharfedale_sdk::contract::{self, ContractSpend};
use wharfedale_sdk::{Client, Contract, Key, SendOptions, Wallet};

const P2PK: &str = include_str!("../examples/contracts/p2pk.simf");
const WAIT: Duration = Duration::from_secs(60);

#[test]
#[ignore = "needs a running network: WHARFEDALE_RPC, WHARFEDALE_FAUCET"]
fn wallet_issuance_and_contract_flow() {
    let client = Client::new(std::env::var("WHARFEDALE_RPC").expect("WHARFEDALE_RPC"));
    let faucet = Wallet::new(client.clone(), Key::load(std::env::var("WHARFEDALE_FAUCET").expect("WHARFEDALE_FAUCET").as_ref()).unwrap());
    let info = client.chain_info().unwrap();
    let (alice, bob) = (Wallet::new(client.clone(), Key::generate()), Wallet::new(client.clone(), Key::generate()));

    // Confidential funding, then a confidential payment.
    let fund = faucet.send(&alice.key().address().to_string(), 2_000_000, &SendOptions::default()).unwrap();
    client.wait_for_tx(&fund, WAIT).unwrap();
    let pay = alice.send(&bob.key().address().to_string(), 500_000, &SendOptions::default()).unwrap();
    client.wait_for_tx(&pay, WAIT).unwrap();
    assert_eq!(alice.balances().unwrap()[&info.fee_asset], 2_000_000 - 500_000 - 1_000);
    assert_eq!(bob.balances().unwrap()[&info.fee_asset], 500_000);

    // Issue and reissue.
    let issued = alice.issue(1_000, 1, 1_000).unwrap();
    client.wait_for_tx(&issued.txid, WAIT).unwrap();
    let mut tries = 0;
    while client.asset(&issued.asset).is_err() && tries < 120 {
        std::thread::sleep(Duration::from_millis(250));
        tries += 1;
    }
    let re = alice.reissue(issued.asset, 250, 1_000).unwrap();
    client.wait_for_tx(&re, WAIT).unwrap();
    assert_eq!(alice.balances().unwrap()[&issued.asset], 1_250);

    // A named issuance: the node verifies the on-chain metadata and serves it.
    let meta = wharfedale_sdk::AssetMetadata::new("Demo Points", "DPT", 2).unwrap();
    let named = alice.issue_named(10_000, 0, 1_000, &meta).unwrap();
    client.wait_for_tx(&named.txid, WAIT).unwrap();
    let mut record = serde_json::Value::Null;
    for _ in 0..120 {
        if let Ok(r) = client.rest(&format!("asset/{}", named.asset)) {
            record = r;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!((record["name"].as_str(), record["ticker"].as_str(), record["precision"].as_u64()), (Some("Demo Points"), Some("DPT"), Some(2)));

    // Lock to bob's p2pk contract, spend with bob's signature.
    let c = Contract::compile(P2PK, &json!({ "OWNER": format!("0x{}", bob.key().xonly_public_key()) }).to_string()).unwrap();
    let lock = faucet.send(&c.address().to_string(), 100_000, &SendOptions::default()).unwrap();
    client.wait_for_tx(&lock, WAIT).unwrap();
    let bob_key = bob.key().clone();
    let signer = move |_: &str| Ok(bob_key.clone());
    let spend = ContractSpend::new(alice.key().address().to_string(), 50_000, json!({ "SIG": "sign:bob" }));
    let txid = contract::spend(&client, &c, &spend, &signer).unwrap();
    client.wait_for_tx(&txid, WAIT).unwrap();
    let left: u64 = contract::coins(&client, &c).unwrap().iter().map(|c| c.value()).sum();
    assert_eq!(left, 100_000 - 50_000 - 1_000);
}
