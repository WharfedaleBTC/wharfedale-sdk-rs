# wharfedale-sdk (Rust)

Client SDK for Wharfedale, a private L1 using the Elements transaction format. Depends only on
crates.io (rust-elements 0.27, simplicity-lang 0.9, simplicityhl 0.9): no node code.

| Module | Contents |
|---|---|
| `Key` | One secret → key-path taproot output, blinding key (`SHA-256("wharfedale/blinding-key" ‖ secret)`), `wfc1…` / `wf1…` addresses; key files `{"secret": "<hex>"}` |
| `Client` | Blocking JSON-RPC + Esplora REST client (one base URL): chain info, transactions, `getscriptutxos`, `testmempoolaccept`, assets, waits |
| `Wallet` | Coins (confidential ones unblinded), balances, `send` / `issue` / `reissue` (and `build_*` without broadcasting) |
| `wallet::{blind, sign_key_path, select, …}` | Building blocks for custom transactions |
| `contract` | SimplicityHL: `Contract::compile`, address, `satisfy`, `spend`; `sig_all_hash`; `signature_artifact` for clients without a compiler |
| `taproot`, `network` | Protocol constants shared with the node (NUMS key, leaf `0xbe`, address params, fee asset) |

```rust
use wharfedale_sdk::{Client, Key, SendOptions, Wallet};

let wallet = Wallet::new(Client::new("http://127.0.0.1:18443"), Key::load("alice.json".as_ref())?);
println!("{}", wallet.key().address());
let txid = wallet.send("wfc1p…", 100_000, &SendOptions::default())?;
wallet.client().wait_for_tx(&txid, std::time::Duration::from_secs(60))?;
# Ok::<(), wharfedale_sdk::Error>(())
```

Contracts: `examples/contracts/*.simf`. A witness value `"sign:<id>"` becomes a BIP340
signature over the input's `sig_all_hash` by the key your `signer(id)` returns.

## Tests

| | |
|---|---|
| `cargo test` | Offline: keys, destinations, contracts, artifact = satisfied program, vectors |
| `tests/vectors.json` | Cross-SDK vectors (keys, addresses, fee assets, contract outputs, `sig_all_hash` over explicit / confidential / issuance / reissuance / annex transactions). Regenerate: `UPDATE_VECTORS=1 cargo test --test vectors`; copy to the TS SDK |
| `cargo test --test e2e -- --ignored` | Against a network: `WHARFEDALE_RPC`, `WHARFEDALE_FAUCET` (e.g. `wharfedale/docker`) |

The node workspace (`../wharfedale`) uses this crate by path: `wharfedale-wallet` is a CLI over it,
and `crates/node/tests/transfer.rs` checks the constants match the node's.
