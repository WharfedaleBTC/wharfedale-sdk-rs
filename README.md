# wharfedale-sdk (Rust)

Client SDK for Wharfedale, a private layer-1 using the Elements (Liquid) transaction format:
confidential assets, issuance, and Simplicity contracts. It talks to any node's JSON-RPC and
Esplora REST API and depends only on crates.io (rust-elements 0.27, simplicity-lang 0.9,
simplicityhl 0.9), not on node code.

## What you can do

| Task | API |
|---|---|
| Create, save and load keys; derive confidential `wfc1…` and explicit `wf1…` addresses | [`Key`](#keys-and-addresses) |
| Read chain state, transactions, assets and address history from a node | [`Client`](#talking-to-a-node) |
| Find your coins (confidential ones are unblinded automatically) and see balances | [`Wallet::coins`, `Wallet::balances`](#balances) |
| Pay confidentially or explicitly, in the fee asset or any issued asset | [`Wallet::send`](#payments) |
| Build and inspect a transaction without broadcasting; dry-run it on the node | [`Wallet::build_send`, `Client::test_accept`](#build-dry-run-broadcast) |
| Issue new assets with reissuance tokens; reissue more later | [`Wallet::issue`, `Wallet::reissue`](#issuing-assets) |
| Assemble custom transactions from building blocks (selection, blinding, signing) | [`wallet::*`](#custom-transactions) |
| Write SimplicityHL contracts, lock coins to them and spend them | [`Contract`, `contract::spend`](#simplicity-contracts) |
| Use time locks and other covenants enforced by Simplicity | [Time-locked contract](#time-locked-contract) |
| Hand a contract to the TypeScript SDK (no compiler in JS) | [`Contract::signature_artifact`](#export-for-typescript) |
| Compute Simplicity's `sig_all_hash` to sign with an external signer | [`contract::sig_all_hash`](#external-signing) |

Every example below is a complete program; `cargo test` compiles them all (see the end of
this file).

## Install

The crate is not on crates.io. Use it by path (as the node's `wharfedale-wallet` does):

```toml
[dependencies]
wharfedale-sdk = { path = "../wharfedale-sdk-rs" }
```

Use `wharfedale_sdk::elements` instead of adding rust-elements yourself, so the versions
always match.

A local network for trying things out: `docker compose -f docker/compose.yml up -d --build` in
the node repository starts four validators with RPC on `http://127.0.0.1:18443`–`18446`.
`docker compose -f docker/compose.yml cp node0:/net/faucet.json .` copies out a funded key.

## Keys and addresses

One 32-byte secret gives everything a wallet needs:

- **Output script**: key-path-only taproot `OP_1 <Q>`.
- **Blinding key**: SHA-256("wharfedale/blinding-key" ‖ secret).
- **Confidential address** `wfc1p…`: what you hand out to get paid privately.
- **Explicit address** `wf1p…`: amounts and assets visible on chain.

```rust,no_run
use wharfedale_sdk::Key;

fn main() -> Result<(), wharfedale_sdk::Error> {
    let key = Key::generate();
    key.save("alice.json".as_ref())?; // {"secret": "<hex>"}, same format as node keys
    let key = Key::load("alice.json".as_ref())?;

    println!("confidential: {}", key.address()); // wfc1p…
    println!("explicit:     {}", key.explicit_address()); // wf1p…
    println!("pubkey:       {}", key.xonly_public_key()); // for contract arguments
    Ok(())
}
```

## Talking to a node

`Client` covers JSON-RPC and Esplora REST, which the node serves on the same base URL. Calls
are blocking.

```rust,no_run
use std::time::Duration;
use wharfedale_sdk::Client;

fn main() -> Result<(), wharfedale_sdk::Error> {
    let client = Client::new("http://127.0.0.1:18443");
    let info = client.chain_info()?;
    println!("{} at height {}, fee asset {}", info.chain, info.blocks, info.fee_asset);

    client.wait_for_height(info.blocks + 1, Duration::from_secs(30))?;

    // Any Esplora endpoint, as JSON.
    let tip = client.rest_text("blocks/tip/hash")?;
    let block = client.rest(&format!("block/{tip}"))?;
    println!("tip has {} transactions", block["tx_count"]);

    // Any JSON-RPC method.
    let mempool = client.call("getrawmempool", serde_json::json!([]))?;
    println!("mempool: {mempool}");
    Ok(())
}
```

## Balances

`Wallet` pairs a key with a client. `coins()` returns confirmed outputs paying the key that are
not already spent in the node's mempool. Confidential outputs are unblinded with the key's
blinding key: you see their asset and amount, while everyone else sees only commitments.

```rust,no_run
use wharfedale_sdk::{Client, Key, Wallet};

fn main() -> Result<(), wharfedale_sdk::Error> {
    let wallet = Wallet::new(Client::new("http://127.0.0.1:18443"), Key::load("alice.json".as_ref())?);

    for (asset, amount) in wallet.balances()? {
        println!("{asset}: {amount}");
    }
    for coin in wallet.coins()? {
        let kind = if coin.confidential { "confidential" } else { "explicit" };
        println!("{}  {} of {}  ({kind})", coin.outpoint, coin.value(), coin.asset());
    }
    Ok(())
}
```

## Payments

`send` picks coins (largest first), adds change and a fee output, blinds, signs every input
and broadcasts:

- To a `wfc1…` address, the payment is blinded to the receiver: amount and asset are hidden on
  chain.
- Change is blinded back to you whenever the transaction is confidential (a confidential
  destination, or any confidential coin spent).
- To a `wf1…` address or a raw hex script, the payment is explicit.

```rust,no_run
use std::time::Duration;
use wharfedale_sdk::elements::AssetId;
use wharfedale_sdk::{Client, Key, SendOptions, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("http://127.0.0.1:18443");
    let alice = Wallet::new(client.clone(), Key::load("alice.json".as_ref())?);
    let bob = Key::load("bob.json".as_ref())?;

    // Confidential payment in the fee asset (fee: 1 000 units by default).
    let txid = alice.send(&bob.address().to_string(), 250_000, &SendOptions::default())?;
    let height = client.wait_for_tx(&txid, Duration::from_secs(60))?;
    println!("{txid} confirmed at {height}");

    // Explicit payment of an issued asset, with a larger fee.
    let asset: AssetId = "6e8da0e6433b5189d819180caeab100f1f8a88e58feabcbcaa2a357d2d28f0f6".parse()?;
    let opts = SendOptions { asset: Some(asset), fee: 2_000 };
    alice.send(&bob.explicit_address().to_string(), 10, &opts)?;
    Ok(())
}
```

## Build, dry-run, broadcast

Every operation has a `build_*` form that returns the signed transaction without sending it.
You can store it, inspect it, or ask the node whether it would accept it
(`testmempoolaccept`, which never changes the node's mempool).

```rust,no_run
use wharfedale_sdk::{Client, Key, SendOptions, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("http://127.0.0.1:18443");
    let alice = Wallet::new(client.clone(), Key::load("alice.json".as_ref())?);
    let bob = Key::load("bob.json".as_ref())?;

    let tx = alice.build_send(&bob.address().to_string(), 1_000, &SendOptions::default())?;
    println!("txid {}, weight {}", tx.txid(), tx.weight());
    for (i, out) in tx.output.iter().enumerate() {
        println!("output {i}: confidential value = {}", out.value.is_confidential());
    }

    match client.test_accept(&tx)? {
        Ok(()) => println!("accepted: {}", client.send_transaction(&tx)?),
        Err(reason) => println!("the node would reject it: {reason}"),
    }
    Ok(())
}
```

## Issuing assets

`issue` creates a new asset from one of your inputs, with optional reissuance tokens. The asset
and tokens are paid confidentially to you. Whoever holds a token can `reissue` (mint more)
later; the token comes back to you. Supply is public: the issued amounts are explicit, and the
node's Esplora `/asset/:id` reports the totals.

```rust,no_run
use std::time::Duration;
use wharfedale_sdk::{Client, Key, SendOptions, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("http://127.0.0.1:18443");
    let issuer = Wallet::new(client.clone(), Key::load("alice.json".as_ref())?);

    // 1 000 000 units and 1 reissuance token (0 tokens = fixed supply). Fee 1 000.
    let issued = issuer.issue(1_000_000, 1, 1_000)?;
    client.wait_for_tx(&issued.txid, Duration::from_secs(60))?;
    println!("asset {}, reissuance token {}", issued.asset, issued.token);

    // Reissuing needs the asset's issuance record, which the node indexes shortly after the block.
    while client.asset(&issued.asset).is_err() {
        std::thread::sleep(Duration::from_millis(250));
    }
    let txid = issuer.reissue(issued.asset, 500_000, 1_000)?;
    client.wait_for_tx(&txid, Duration::from_secs(60))?;
    println!("supply now {:?}", client.asset(&issued.asset)?.issued_amount);

    // Issued assets are paid like any other.
    let bob = Key::load("bob.json".as_ref())?;
    issuer.send(&bob.address().to_string(), 42, &SendOptions { asset: Some(issued.asset), ..Default::default() })?;
    Ok(())
}
```

## Custom transactions

The `wallet` module exposes the steps `send` uses, so you can shape a transaction yourself.
This example pays two receivers from one transaction, one confidentially and one explicitly:

```rust,no_run
use wharfedale_sdk::elements::TxOut;
use wharfedale_sdk::network::destination;
use wharfedale_sdk::wallet::{blind, output_to, select, sign_key_path, unsigned_tx};
use wharfedale_sdk::{Client, Key, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("http://127.0.0.1:18443");
    let key = Key::load("alice.json".as_ref())?;
    let wallet = Wallet::new(client.clone(), key.clone());
    let info = client.chain_info()?;
    let fee = 1_500;

    // Two payees: a wfc1 address (blinded) and a wf1 address (explicit).
    let (bob_spk, bob_blinder) = destination(&Key::load("bob.json".as_ref())?.address().to_string())?;
    let (carol_spk, _) = destination(&Key::load("carol.json".as_ref())?.explicit_address().to_string())?;
    let (pay_bob, pay_carol) = (100_000, 50_000);

    let mut pool = wallet.coins()?;
    let (inputs, total) = select(&mut pool, info.fee_asset, pay_bob + pay_carol + fee)?;
    let change = total - pay_bob - pay_carol - fee;

    let mut tx = unsigned_tx(
        &inputs,
        vec![
            output_to(bob_spk, info.fee_asset, pay_bob, bob_blinder),
            output_to(carol_spk, info.fee_asset, pay_carol, None),
            output_to(key.script_pubkey(), info.fee_asset, change, Some(key.blinding_public_key())),
            TxOut::new_fee(fee, info.fee_asset),
        ],
    );
    // Surjection domain: the opening of each spent coin, in input order.
    let domain: Vec<_> = inputs.iter().map(|c| c.secrets).collect();
    blind(&mut tx, &domain)?;
    let prevouts: Vec<TxOut> = inputs.iter().map(|c| c.txout.clone()).collect();
    sign_key_path(&mut tx, &prevouts, &key, info.genesis_hash)?;

    println!("{}", client.send_transaction(&tx)?);
    Ok(())
}
```

Rules the node enforces (see the node docs, "Validation"):

- Outputs are taproot, fee (empty script) or `OP_RETURN` (explicit only).
- A transaction spending confidential coins must have at least one blinded output.
- Fees are paid in the chain's fee asset (`chain_info().fee_asset`). The minimum is 100 units
  per 1 000 vbytes.

## Simplicity contracts

Contracts are written in [SimplicityHL](https://github.com/BlockstreamResearch/SimplicityHL)
and compiled with their arguments into a Simplicity program. The program's commitment Merkle
root (CMR) defines a taproot output with a single Simplicity leaf and no key path, so coins
sent there move only when the program accepts the spending transaction. Every validator runs
the program (the same C library Elements uses).

`examples/contracts/p2pk.simf`, "pay to public key":

```text
fn main() {
    jet::bip_0340_verify((param::OWNER, jet::sig_all_hash()), witness::SIG)
}
```

Lock coins to Bob's key, then let Bob spend them:

```rust,no_run
use std::time::Duration;
use serde_json::json;
use wharfedale_sdk::contract::{self, ContractSpend};
use wharfedale_sdk::{Client, Contract, Key, SendOptions, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("http://127.0.0.1:18443");
    let funder = Wallet::new(client.clone(), Key::load("faucet.json".as_ref())?);
    let bob = Key::load("bob.json".as_ref())?;
    let alice = Key::load("alice.json".as_ref())?;

    // Compile with arguments: OWNER = Bob's x-only public key.
    let source = std::fs::read_to_string("examples/contracts/p2pk.simf")?;
    let args = json!({ "OWNER": format!("0x{}", bob.xonly_public_key()) });
    let p2pk = Contract::compile(&source, &args.to_string())?;
    println!("contract {} (cmr {})", p2pk.address(), hex::encode(p2pk.cmr()));

    // Anyone can pay the contract (contract outputs are explicit).
    let lock = funder.send(&p2pk.address().to_string(), 100_000, &SendOptions::default())?;
    client.wait_for_tx(&lock, Duration::from_secs(60))?;

    // Spend: "sign:<id>" in the witness becomes a signature by the key `signer(id)` returns,
    // over this input's sig_all_hash. The fee is paid from the contract; change returns to it.
    let spend = ContractSpend::new(alice.address().to_string(), 60_000, json!({ "SIG": "sign:bob" }));
    let signer = |id: &str| match id {
        "bob" => Ok(bob.clone()),
        other => Err(wharfedale_sdk::Error::Key(format!("unknown signer {other}"))),
    };
    let txid = contract::spend(&client, &p2pk, &spend, &signer)?;
    client.wait_for_tx(&txid, Duration::from_secs(60))?;

    let left: u64 = contract::coins(&client, &p2pk)?.iter().map(|c| c.value()).sum();
    println!("left in contract: {left}"); // 100 000 − 60 000 − 1 000
    Ok(())
}
```

Before anything is broadcast, the SDK runs the program against the transaction (to prune it,
as consensus requires). A wrong signature or an unmet condition therefore fails locally with
`Error::Contract("not satisfied: …")`.

### Time-locked contract

`examples/contracts/timelock.simf` pays `OWNER` only once the spending transaction's lock time
is at least `AFTER` (a block height). Consensus enforces lock times, so the covenant holds:

```text
fn main() {
    let after: Height = param::AFTER;
    jet::check_lock_height(after);
    jet::bip_0340_verify((param::OWNER, jet::sig_all_hash()), witness::SIG)
}
```

```rust,no_run
use serde_json::json;
use wharfedale_sdk::contract::{self, ContractSpend};
use wharfedale_sdk::{Client, Contract, Key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("http://127.0.0.1:18443");
    let owner = Key::load("bob.json".as_ref())?;
    let unlock_at = client.block_count()? + 10;

    let source = std::fs::read_to_string("examples/contracts/timelock.simf")?;
    let args = json!({ "OWNER": format!("0x{}", owner.xonly_public_key()), "AFTER": unlock_at.to_string() });
    let vault = Contract::compile(&source, &args.to_string())?;
    println!("send coins to {}; spendable from height {unlock_at}", vault.address());

    // Later, once the chain has passed `unlock_at`:
    let mut spend = ContractSpend::new(owner.address().to_string(), 10_000, json!({ "SIG": "sign:owner" }));
    spend.lock_time = Some(unlock_at as u32); // below AFTER: "not satisfied"; above the tip: not final yet
    let txid = contract::spend(&client, &vault, &spend, &|_| Ok(owner.clone()))?;
    println!("{txid}");
    Ok(())
}
```

### Export for TypeScript

The TypeScript SDK has no SimplicityHL compiler. It can still spend contracts that have no
branches and whose witness is only signatures (p2pk, timelock + signature, n-of-n multisig),
using an artifact compiled here:

```rust,no_run
use serde_json::json;
use wharfedale_sdk::{Contract, Key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let owner = Key::load("bob.json".as_ref())?;
    let source = std::fs::read_to_string("examples/contracts/p2pk.simf")?;
    let p2pk = Contract::compile(&source, &json!({ "OWNER": format!("0x{}", owner.xonly_public_key()) }).to_string())?;

    // {"cmr": "...", "program": "...", "signatures": ["SIG"]}
    let artifact = p2pk.signature_artifact()?;
    std::fs::write("p2pk.artifact.json", serde_json::to_vec_pretty(&artifact)?)?;
    Ok(())
}
```

The CLI does the same: `wharfedale-wallet contract-artifact --program p2pk.simf --args p2pk.args`.

### External signing

To sign with a key the SDK doesn't hold (a hardware device, a remote signer), compute the
message yourself. Contract signatures are BIP340 over Simplicity's `sig_all_hash`, which commits
to the whole transaction, every spent output, the input index, the program and the chain's
genesis hash:

```rust,no_run
use wharfedale_sdk::elements::{Transaction, TxOut};
use wharfedale_sdk::{contract, Client, Contract};

fn message_to_sign(client: &Client, c: &Contract, tx: &Transaction, prevouts: &[TxOut], input: u32)
    -> Result<[u8; 32], wharfedale_sdk::Error> {
    let genesis = client.chain_info()?.genesis_hash;
    Ok(contract::sig_all_hash(tx, prevouts, input, &c.cmr(), genesis))
}

fn main() {}
```

`contract::build_spend` returns the finished transaction without broadcasting it, if you want to
inspect it first.

## Errors

Every call returns `wharfedale_sdk::Result<T>`; [`Error`](src/error.rs) separates:

- node rejections (`Rpc { method, message }`, e.g. `invalid: input 0: signature verification failed`);
- transport failures (`Http`);
- `InsufficientFunds { asset, have, need }`;
- bad addresses (`Destination`);
- contract compile or satisfaction failures (`Contract`);
- timeouts while waiting (`Timeout`).

## Tests

| Command | Covers |
|---|---|
| `cargo test` | Offline: keys, destinations, contracts, artifact equals the satisfied program, cross-SDK vectors, and every example in this README (compiled as doctests) |
| `UPDATE_VECTORS=1 cargo test --test vectors` | Regenerate `tests/vectors.json` (keys, addresses, fee assets, contract outputs, `sig_all_hash`), then copy it to the TypeScript SDK |
| `WHARFEDALE_RPC=… WHARFEDALE_FAUCET=… cargo test --test e2e -- --ignored` | Payments, issuance, reissuance and a contract spend against a live network |

The node workspace (`../wharfedale`) uses this crate by path: `wharfedale-wallet` is a CLI over
it, and the node's tests check that the SDK's protocol constants match the node's.
