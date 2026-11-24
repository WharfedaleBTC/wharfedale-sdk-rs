//! Client SDK for [Wharfedale](https://github.com/), a private layer-1 using the Elements
//! transaction format.
//!
//! - [`Key`]: one secret → key-path taproot output, blinding key, `wfc1…`/`wf1…` addresses.
//! - [`Client`]: the node's JSON-RPC and Esplora REST API (same base URL).
//! - [`Wallet`]: coin discovery (unblinding), confidential payments, issuance, reissuance.
//! - [`contract`]: SimplicityHL contracts — compile, address, spend; `sig_all_hash`.
//! - [`taproot`], [`network`]: protocol constants shared with the node.
//!
//! ```no_run
//! use wharfedale_sdk::{Client, Key, Wallet, SendOptions};
//! let wallet = Wallet::new(Client::new("http://127.0.0.1:18443"), Key::generate());
//! println!("receive at {}", wallet.key().address());
//! let txid = wallet.send("wfc1p…", 1_000, &SendOptions::default())?;
//! # Ok::<(), wharfedale_sdk::Error>(())
//! ```
#![forbid(unsafe_code)]

pub mod client;
pub mod contract;
mod error;
pub mod keys;
pub mod metadata;
pub mod network;
pub mod taproot;
pub mod wallet;

pub use client::{ChainInfo, Client};
pub use contract::Contract;
pub use error::{Error, Result};
pub use keys::Key;
pub use metadata::AssetMetadata;
pub use wallet::{Coin, Issued, SendOptions, Wallet};

/// Re-exported so applications use the exact rust-elements version the SDK does.
pub use elements;

/// Compiles every example in README.md (`cargo test --doc`).
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
