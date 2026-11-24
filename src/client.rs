//! Blocking client for a node's JSON-RPC (`POST /`) and Esplora REST (`GET /…`) API, served on
//! the same base URL.

use std::str::FromStr;
use std::time::{Duration, Instant};

use elements::{encode, AssetId, BlockHash, Script, Transaction, Txid};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct Client {
    url: String,
    agent: ureq::Agent,
}

/// `getblockchaininfo`, the fields a wallet needs.
#[derive(Clone, Debug)]
pub struct ChainInfo {
    pub chain: String,
    pub blocks: u64,
    pub best_block_hash: BlockHash,
    pub genesis_hash: BlockHash,
    pub fee_asset: AssetId,
}

/// One entry of `getscriptutxos`.
#[derive(Clone, Debug)]
pub struct ScriptUtxo {
    pub txid: Txid,
    pub vout: u32,
    pub height: Option<u64>,
    /// Spent by a transaction in the node's mempool.
    pub spent_in_mempool: bool,
}

#[derive(Deserialize)]
struct RawScriptUtxo {
    txid: String,
    vout: u32,
    #[serde(default)]
    height: Option<u64>,
    #[serde(default)]
    spent_in_mempool: bool,
}

/// Esplora `/asset/:id` fields needed to reissue.
#[derive(Clone, Debug)]
pub struct AssetRecord {
    pub asset: AssetId,
    pub reissuance_token: Option<AssetId>,
    /// Issuance entropy (internal byte order).
    pub entropy: [u8; 32],
    pub issued_amount: Option<u64>,
}

impl Client {
    /// `url`: e.g. `http://127.0.0.1:18443`.
    pub fn new(url: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
        Self { url: url.into().trim_end_matches('/').to_string(), agent }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Any JSON-RPC method.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let resp = self
            .agent
            .post(&self.url)
            .send_json(json!({ "jsonrpc": "1.0", "id": "sdk", "method": method, "params": params }));
        let body: Value = match resp {
            Ok(r) => r.into_json()?,
            // JSON-RPC errors may come with a non-200 status and a JSON body.
            Err(ureq::Error::Status(_, r)) => r.into_json().map_err(|e| Error::Http(e.to_string()))?,
            Err(e) => return Err(Error::Http(e.to_string())),
        };
        match body.get("error") {
            Some(e) if !e.is_null() => Err(Error::Rpc {
                method: method.to_string(),
                message: e.get("message").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| e.to_string()),
            }),
            _ => Ok(body.get("result").cloned().unwrap_or(Value::Null)),
        }
    }

    /// Esplora `GET <url>/<path>` as JSON.
    pub fn rest(&self, path: &str) -> Result<Value> {
        let text = self.rest_text(path)?;
        serde_json::from_str(&text).map_err(|e| Error::Response(format!("{path}: {e}")))
    }

    /// Esplora `GET <url>/<path>` as text (e.g. `blocks/tip/height`).
    pub fn rest_text(&self, path: &str) -> Result<String> {
        let url = format!("{}/{}", self.url, path.trim_start_matches('/'));
        self.agent.get(&url).call().map_err(|e| Error::Http(format!("GET {path}: {e}")))?.into_string().map_err(Error::from)
    }

    pub fn chain_info(&self) -> Result<ChainInfo> {
        let v = self.call("getblockchaininfo", json!([]))?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).ok_or_else(|| Error::Response(format!("getblockchaininfo: no {k}")));
        Ok(ChainInfo {
            chain: s("chain")?.to_string(),
            blocks: v.get("blocks").and_then(Value::as_u64).ok_or_else(|| Error::Response("getblockchaininfo: no blocks".into()))?,
            best_block_hash: parse(s("bestblockhash")?)?,
            genesis_hash: parse(s("genesis_hash")?)?,
            fee_asset: parse(s("fee_asset")?)?,
        })
    }

    pub fn block_count(&self) -> Result<u64> {
        self.call("getblockcount", json!([]))?.as_u64().ok_or_else(|| Error::Response("getblockcount".into()))
    }

    /// A confirmed or mempool transaction.
    pub fn transaction(&self, txid: &Txid) -> Result<Transaction> {
        let v = self.call("getrawtransaction", json!([txid.to_string()]))?;
        decode_tx(v.as_str().ok_or_else(|| Error::Response("getrawtransaction".into()))?)
    }

    /// Height of the block containing `txid`; `None` while unconfirmed.
    pub fn tx_height(&self, txid: &Txid) -> Result<Option<u64>> {
        let v = self.call("getrawtransaction", json!([txid.to_string(), true]))?;
        Ok(v.get("blockheight").and_then(Value::as_u64))
    }

    /// `sendrawtransaction`: admitted to the node's mempool and gossiped.
    pub fn send_transaction(&self, tx: &Transaction) -> Result<Txid> {
        let v = self.call("sendrawtransaction", json!([hex::encode(encode::serialize(tx))]))?;
        parse(v.as_str().ok_or_else(|| Error::Response("sendrawtransaction".into()))?)
    }

    /// `testmempoolaccept` for one transaction: `Ok(())` or the reject reason. Never admits.
    pub fn test_accept(&self, tx: &Transaction) -> Result<std::result::Result<(), String>> {
        let v = self.call("testmempoolaccept", json!([[hex::encode(encode::serialize(tx))]]))?;
        let r = v.get(0).ok_or_else(|| Error::Response("testmempoolaccept".into()))?;
        if r.get("allowed").and_then(Value::as_bool) == Some(true) {
            Ok(Ok(()))
        } else {
            Ok(Err(r.get("reject-reason").and_then(Value::as_str).unwrap_or("rejected").to_string()))
        }
    }

    /// Confirmed unspent outputs locked to `script_pubkey` (`getscriptutxos`).
    pub fn script_utxos(&self, script_pubkey: &Script) -> Result<Vec<ScriptUtxo>> {
        let v = self.call("getscriptutxos", json!([hex::encode(script_pubkey.as_bytes())]))?;
        let raw: Vec<RawScriptUtxo> = serde_json::from_value(v)?;
        raw.into_iter()
            .map(|u| Ok(ScriptUtxo { txid: parse(&u.txid)?, vout: u.vout, height: u.height, spent_in_mempool: u.spent_in_mempool }))
            .collect()
    }

    /// Esplora `/asset/:id`.
    pub fn asset(&self, asset: &AssetId) -> Result<AssetRecord> {
        let v = self.rest(&format!("asset/{asset}"))?;
        let entropy = v
            .get("entropy")
            .and_then(Value::as_str)
            .and_then(|e| hex::decode(e).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| Error::Response("asset record has no entropy".into()))?;
        Ok(AssetRecord {
            asset: *asset,
            reissuance_token: v.get("reissuance_token").and_then(Value::as_str).map(parse).transpose()?,
            entropy,
            issued_amount: v.pointer("/chain_stats/issued_amount").and_then(Value::as_u64),
        })
    }

    /// Waits until `txid` is in a block; returns its height.
    pub fn wait_for_tx(&self, txid: &Txid, timeout: Duration) -> Result<u64> {
        poll(timeout, &format!("transaction {txid} not confirmed"), || self.tx_height(txid).ok().flatten())
    }

    /// Waits until the chain reaches `height`; returns the tip height.
    pub fn wait_for_height(&self, height: u64, timeout: Duration) -> Result<u64> {
        poll(timeout, &format!("height {height} not reached"), || self.block_count().ok().filter(|h| *h >= height))
    }
}

fn poll<T>(timeout: Duration, what: &str, mut f: impl FnMut() -> Option<T>) -> Result<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Ok(v);
        }
        if Instant::now() > deadline {
            return Err(Error::Timeout(what.to_string()));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn parse<T: FromStr>(s: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    T::from_str(s).map_err(|e| Error::Response(format!("{s}: {e}")))
}

/// Decodes a hex-encoded Elements transaction.
pub fn decode_tx(hex_tx: &str) -> Result<Transaction> {
    let bytes = hex::decode(hex_tx).map_err(|e| Error::Response(e.to_string()))?;
    encode::deserialize(&bytes).map_err(|e| Error::Response(e.to_string()))
}
