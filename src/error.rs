use thiserror::Error;

/// Main error type for GhostLink operations
#[derive(Error, Debug)]
pub enum GhostLinkError {
    /// gRPC transport errors
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::transport::Error),
    
    /// gRPC status errors
    #[error("gRPC status: {0}")]
    Status(#[from] tonic::Status),
    
    /// Connection errors
    #[error("Connection error: {0}")]
    Connection(String),
    
    /// Authentication/cryptography errors
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    /// Domain resolution errors
    #[error("Domain resolution failed: {0}")]
    DomainResolution(String),
    
    /// Blockchain transaction errors
    #[error("Transaction error: {0}")]
    Transaction(String),
    
    /// Smart contract errors (ZVM related)
    #[error("Smart contract error: {0}")]
    SmartContract(String),
    
    /// Cache errors
    #[error("Cache error: {0}")]
    Cache(String),
    
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// Generic errors
    #[error("Error: {0}")]
    Other(#[from] anyhow::Error),
}

/// Result type alias for GhostLink operations
pub type Result<T> = std::result::Result<T, GhostLinkError>;

impl From<url::ParseError> for GhostLinkError {
    fn from(err: url::ParseError) -> Self {
        GhostLinkError::Config(format!("Invalid URL: {}", err))
    }
}
