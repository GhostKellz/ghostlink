use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("proto");
    
    // Ensure proto directory exists
    std::fs::create_dir_all(&proto_dir)?;
    
    // Create basic proto files for GhostChain ecosystem
    create_ghostchain_proto(&proto_dir)?;
    create_ghostid_proto(&proto_dir)?;
    create_zns_proto(&proto_dir)?;
    
    // Build protobuf files
    let proto_files = [
        "proto/ghostchain.proto",
        "proto/ghostid.proto", 
        "proto/zns.proto",
    ];
    
    tonic_build::configure()
        .build_server(false) // GhostLink is client-only
        .build_client(true)
        .compile_protos(&proto_files, &["proto"])?;
        
    // Tell Cargo to recompile if proto files change
    for file in &proto_files {
        println!("cargo:rerun-if-changed={}", file);
    }

    // Link ZVM library if feature is enabled
    #[cfg(feature = "zvm")]
    {
        println!("cargo:rustc-link-lib=zvm");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
        println!("cargo:rustc-link-search=native=./zvm/lib");
        
        // Tell cargo to rerun if ZVM changes
        println!("cargo:rerun-if-changed=zvm/");
        println!("cargo:rerun-if-env-changed=ZVM_LIB_PATH");
        
        // Use custom ZVM path if provided
        if let Ok(zvm_path) = std::env::var("ZVM_LIB_PATH") {
            println!("cargo:rustc-link-search=native={}", zvm_path);
        }
    }
    
    Ok(())
}

fn create_ghostchain_proto(proto_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let proto_content = r#"syntax = "proto3";

package ghostchain.v1;

// GhostChain blockchain service
service GhostChain {
    // Wallet operations
    rpc GetBalance(BalanceRequest) returns (BalanceResponse);
    rpc SendTransaction(TransactionRequest) returns (TransactionResponse);
    rpc GetTransactionHistory(HistoryRequest) returns (HistoryResponse);
    
    // Smart contract operations (executed via ZVM)
    rpc DeployContract(DeployContractRequest) returns (DeployContractResponse);
    rpc CallContract(CallContractRequest) returns (CallContractResponse);
    rpc GetContractState(ContractStateRequest) returns (ContractStateResponse);
    
    // Chain info
    rpc GetChainInfo(ChainInfoRequest) returns (ChainInfoResponse);
    rpc GetBlockInfo(BlockInfoRequest) returns (BlockInfoResponse);
}

// Wallet operations
message BalanceRequest {
    string address = 1;
    repeated string tokens = 2; // MANA, SPIRIT, SOUL, RLUSD
}

message BalanceResponse {
    map<string, string> balances = 1; // token -> amount
}

message TransactionRequest {
    string from = 1;
    string to = 2;
    string amount = 3;
    string token = 4;
    bytes signature = 5;
}

message TransactionResponse {
    string transaction_hash = 1;
    bool success = 2;
    string error_message = 3;
}

message HistoryRequest {
    string address = 1;
    int32 limit = 2;
    string cursor = 3;
}

message HistoryResponse {
    repeated Transaction transactions = 1;
    string next_cursor = 2;
}

message Transaction {
    string hash = 1;
    string from = 2;
    string to = 3;
    string amount = 4;
    string token = 5;
    int64 timestamp = 6;
    bool success = 7;
}

// Smart contract operations (ZVM integration)
message DeployContractRequest {
    bytes wasm_code = 1; // WASM-Lite bytecode for ZVM
    bytes constructor_args = 2;
    string deployer = 3;
    bytes signature = 4;
}

message DeployContractResponse {
    string contract_address = 1;
    string transaction_hash = 2;
    bool success = 3;
    string error_message = 4;
}

message CallContractRequest {
    string contract_address = 1;
    string method = 2;
    bytes args = 3;
    string caller = 4;
    bytes signature = 5;
}

message CallContractResponse {
    bytes result = 1;
    bool success = 2;
    string error_message = 3;
    int64 gas_used = 4;
}

message ContractStateRequest {
    string contract_address = 1;
    string key = 2;
}

message ContractStateResponse {
    bytes value = 1;
}

// Chain info
message ChainInfoRequest {}

message ChainInfoResponse {
    string chain_id = 1;
    int64 latest_block = 2;
    string network = 3;
}

message BlockInfoRequest {
    int64 block_number = 1;
}

message BlockInfoResponse {
    int64 number = 1;
    string hash = 2;
    string parent_hash = 3;
    int64 timestamp = 4;
    repeated string transaction_hashes = 5;
}
"#;
    
    std::fs::write(proto_dir.join("ghostchain.proto"), proto_content)?;
    Ok(())
}

fn create_ghostid_proto(proto_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let proto_content = r#"syntax = "proto3";

package ghostid.v1;

// GhostID identity service
service GhostID {
    rpc CreateIdentity(CreateIdentityRequest) returns (CreateIdentityResponse);
    rpc GetIdentity(GetIdentityRequest) returns (GetIdentityResponse);
    rpc UpdateIdentity(UpdateIdentityRequest) returns (UpdateIdentityResponse);
    rpc VerifyIdentity(VerifyIdentityRequest) returns (VerifyIdentityResponse);
}

message CreateIdentityRequest {
    string username = 1;
    string public_key = 2;
    map<string, string> metadata = 3;
    bytes signature = 4;
}

message CreateIdentityResponse {
    string identity_id = 1;
    bool success = 2;
    string error_message = 3;
}

message GetIdentityRequest {
    string identity_id = 1;
}

message GetIdentityResponse {
    GhostIdentity identity = 1;
}

message UpdateIdentityRequest {
    string identity_id = 1;
    map<string, string> metadata = 2;
    bytes signature = 3;
}

message UpdateIdentityResponse {
    bool success = 1;
    string error_message = 2;
}

message VerifyIdentityRequest {
    string identity_id = 1;
    bytes challenge = 2;
    bytes signature = 3;
}

message VerifyIdentityResponse {
    bool valid = 1;
}

message GhostIdentity {
    string identity_id = 1;
    string username = 2;
    string public_key = 3;
    map<string, string> metadata = 4;
    int64 created_at = 5;
    int64 updated_at = 6;
}
"#;
    
    std::fs::write(proto_dir.join("ghostid.proto"), proto_content)?;
    Ok(())
}

fn create_zns_proto(proto_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let proto_content = r#"syntax = "proto3";

package zns.v1;

// ZNS (Zig Name Service) for domain resolution
service ZNS {
    // Domain resolution
    rpc ResolveDomain(ResolveDomainRequest) returns (ResolveDomainResponse);
    rpc ResolveBatch(ResolveBatchRequest) returns (ResolveBatchResponse);
    rpc SubscribeDomainChanges(SubscribeDomainChangesRequest) returns (stream DomainChangeEvent);
    
    // Domain management
    rpc RegisterDomain(RegisterDomainRequest) returns (RegisterDomainResponse);
    rpc UpdateDomain(UpdateDomainRequest) returns (UpdateDomainResponse);
    rpc TransferDomain(TransferDomainRequest) returns (TransferDomainResponse);
    
    // Multi-service resolution (ENS, Unstoppable, etc.)
    rpc ResolveMultiService(ResolveMultiServiceRequest) returns (ResolveMultiServiceResponse);
}

message ResolveDomainRequest {
    string domain = 1;
    repeated string record_types = 2; // A, AAAA, TXT, etc.
}

message ResolveDomainResponse {
    DomainRecord domain_record = 1;
}

message ResolveBatchRequest {
    repeated string domains = 1;
    repeated string record_types = 2;
}

message ResolveBatchResponse {
    repeated DomainRecord domain_records = 1;
}

message SubscribeDomainChangesRequest {
    repeated string domains = 1;
}

message DomainChangeEvent {
    string domain = 1;
    string change_type = 2; // CREATED, UPDATED, DELETED
    DomainRecord new_record = 3;
    int64 timestamp = 4;
}

message RegisterDomainRequest {
    string domain = 1;
    string owner = 2;
    repeated DNSRecord initial_records = 3;
    bytes signature = 4;
}

message RegisterDomainResponse {
    bool success = 1;
    string transaction_hash = 2;
    string error_message = 3;
}

message UpdateDomainRequest {
    string domain = 1;
    repeated DNSRecord records = 2;
    string owner = 3;
    bytes signature = 4;
}

message UpdateDomainResponse {
    bool success = 1;
    string error_message = 2;
}

message TransferDomainRequest {
    string domain = 1;
    string current_owner = 2;
    string new_owner = 3;
    bytes signature = 4;
}

message TransferDomainResponse {
    bool success = 1;
    string transaction_hash = 2;
    string error_message = 3;
}

// Multi-service resolution (ENS, Unstoppable Domains, etc.)
message ResolveMultiServiceRequest {
    string domain = 1;
    repeated string services = 2; // ENS, UNSTOPPABLE, GHOST
    repeated string record_types = 3;
}

message ResolveMultiServiceResponse {
    repeated ServiceResolution resolutions = 1;
}

message ServiceResolution {
    string service = 1;
    bool success = 2;
    DomainRecord record = 3;
    string error_message = 4;
}

message DomainRecord {
    string domain = 1;
    repeated DNSRecord records = 2;
    map<string, string> crypto_addresses = 3; // chain -> address
    string owner_id = 4;
    string resolver = 5;
    bytes signature = 6;
    int64 ttl = 7;
    int64 timestamp = 8;
}

message DNSRecord {
    string type = 1; // A, AAAA, TXT, MX, etc.
    string value = 2;
    int32 ttl = 3;
    int32 priority = 4; // For MX records
}
"#;
    
    std::fs::write(proto_dir.join("zns.proto"), proto_content)?;
    Ok(())
}
