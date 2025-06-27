// Generated protobuf modules
pub mod ghostchain {
    tonic::include_proto!("ghostchain.v1");
}

pub mod ghostid {
    tonic::include_proto!("ghostid.v1");
}

pub mod zns {
    tonic::include_proto!("zns.v1");
}

// Re-export commonly used types
pub use ghostchain::*;
pub use ghostid::*;
pub use zns::*;
