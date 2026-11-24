use elements::AssetId;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The node answered with a JSON-RPC error.
    #[error("RPC {method}: {message}")]
    Rpc { method: String, message: String },
    /// Transport failure or non-success HTTP status.
    #[error("HTTP: {0}")]
    Http(String),
    /// A response that doesn't have the expected shape.
    #[error("unexpected response: {0}")]
    Response(String),
    #[error("insufficient funds in asset {asset}: have {have}, need {need}")]
    InsufficientFunds { asset: AssetId, have: u64, need: u64 },
    #[error("invalid destination {0:?}: neither a Wharfedale address nor a hex script")]
    Destination(String),
    #[error("key: {0}")]
    Key(String),
    #[error("transaction: {0}")]
    Transaction(String),
    #[error("contract: {0}")]
    Contract(String),
    #[error("timed out: {0}")]
    Timeout(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
