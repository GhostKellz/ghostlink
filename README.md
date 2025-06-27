# 👻️ GhostLink
## 🚀 Quick Start

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ghostlink = "0.1.0"

# Enable ZVM integration for smart contracts
ghostlink = { version = "0.1.0", features = ["zvm-integration"] }
```

### Basic Usage

```rust
use ghostlink::{GhostClient, GhostClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to GhostBridge
    let config = GhostClientConfig::builder()
        .endpoint("https://ghostbridge.local:9443")
        .with_tls()
        .build();
    
    let client = GhostClient::connect(config).await?;
    
    // Resolve .ghost domain via ZNS
    let domain = client.zns().resolve_domain("ghostkellz.ghost").await?;
    println!("Resolved: {:?}", domain);
    
    // Check GhostChain wallet balance
    let balance = client.ghostchain()
        .get_balance("ghost1abc123...")
        .await?;
    println!("MANA: {}", balance.get("MANA").unwrap_or(&"0".to_string()));
    
    Ok(())
}
```

### ZVM Smart Contract Integration

```rust
use ghostlink::zvm::{ZVMExecutor, contract::ContractUtils};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut zvm = ZVMExecutor::new()?;
    
    // Deploy an ERC20 token contract
    let bytecode = std::fs::read("token.wasm")?;
    let (contract, result) = zvm.deploy_contract(bytecode, vec![], None).await?;
    println!("Deployed at: 0x{}", hex::encode(contract.address));
    
    // Transfer tokens
    let result = zvm.erc20_transfer(
        contract.address,
        recipient_address,
        1000, // amount
        None  // default gas
    ).await?;
    
    if result.success {
        println!("Transfer successful! Gas used: {}", result.gas_used);
    }
    
    Ok(())
}
```

### CLI Usage

```bash
# Install GhostLink CLI
cargo install ghostlink

# Resolve a .ghost domain
ghostlink resolve ghostkellz.ghost

# Check wallet balance
ghostlink balance ghost1abc123... --token MANA

# Deploy a smart contract (with ZVM feature)
ghostlink contract deploy contract.wasm --gas-limit 1000000

# Call a contract function
ghostlink contract call 0x1234... "transfer(address,uint256)" --args "0x5678...,1000"

# Execute raw ZVM bytecode
ghostlink execute bytecode.bin --gas-limit 50000
```

---

## 🏗️ Architecture

GhostLink operates as a Rust gRPC client in the GhostChain ecosystem:

```
┌─────────────────────┐    gRPC/QUIC     ┌─────────────────────┐
│    GhostLink        │ ←──────────────→ │    GhostBridge      │
│   (Rust Client)     │                  │   (Zig gRPC Server) │
└─────────────────────┘                  └─────────────────────┘
          │                                         │
          │ FFI Calls                               │ 
          ▼                                         ▼
┌─────────────────────┐                  ┌─────────────────────┐
│       ZVM/zEVM      │                  │    GhostChain       │
│   (Zig VM Engine)   │ ←──────────────→ │  (Rust Blockchain)  │
└─────────────────────┘    Smart Contract └─────────────────────┘
                            Execution               │
                                                   │
                                                   ▼
                                         ┌─────────────────────┐
                                         │        ZNS          │
                                         │ (Zig Name Service)  │
                                         └─────────────────────┘
```

### Component Overview

- **GhostLink** (This project): Rust gRPC client with async/await support
- **GhostBridge**: Zig gRPC server providing protocol bridge
- **GhostChain**: Main Rust blockchain with consensus and state management
- **ZVM/zEVM**: Zig Virtual Machine for WASM-Lite smart contract execution
- **ZNS**: Zig Name Service for .ghost/.bc domain resolutione gRPC client/server for the GhostMesh, ZNS, and GhostChain ecosystem — ultra-fast, async, and ready for Web5 and blockchain integrations.**

---

![Crate Downloads](https://img.shields.io/crates/d/ghostlink)
![License](https://img.shields.io/crates/l/ghostlink)
![Rust](https://img.shields.io/badge/Rust-2024-orange)
![QUIC Ready](https://img.shields.io/badge/QUIC-ready-blue)

---

## 🚀 What is GhostLink?

**GhostLink** is the official Rust bridge for GhostMesh infrastructure. It’s built to provide:

* **Async, high-performance gRPC over QUIC** for blockchain and DNS integration.
* **Seamless FFI and protobuf compatibility** with [ghostbridge (Zig)](https://github.com/ghostkellz/ghostbridge).
* **Plug-and-play with ZNS, CNS, zvm/zEVM, and GhostChain**—designed for the next-gen Web5 stack.

---

## 🛠️ Features

* ⚡ **Zero-copy gRPC**: Built on [tonic](https://github.com/hyperium/tonic) & [quinn](https://github.com/quinn-rs/quinn) for QUIC
* 🦀 **Native async/await** for blazing throughput
* 🔐 **Cryptography-ready**: Native zcrypto and Ed25519/BLAKE3 support (zcrypto FFI)
* 🕸️ **Integrated with GhostMesh**: DNS, mesh, and chain queries out of the box
* 📦 **Protobuf-first**: Schema contract with Zig and future language bindings
* 🌍 **Multi-network**: Serve .ghost, .bc, and .chain domains

---

## 📦 Example Usage

```rust
use ghostlink::{GhostClient, DomainQuery};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = GhostClient::connect("https://ghostbridge.local:9443").await?;
    let response = client.resolve_domain(DomainQuery::new("demo.ghost"), &["A", "TXT"]).await?;
    println!("Records: {:?}", response.records);
    Ok(())
}
```

---

## 🌉 Bridge Architecture

* **Rust-first for blockchain nodes, DApps, and dev tooling**
* Mirrors all key GhostBridge (Zig) endpoints for full ecosystem compatibility
* Protobuf schemas shared across Zig and Rust for easy expansion
* Designed for secure, low-latency communication with GhostChain, ZNS, CNS, and more

---

## 💡 Why GhostLink?

* Universal compatibility: plug Rust infra into a growing Zig-powered mesh
* QUIC & gRPC: the next generation of secure, high-speed transport
* Clean async codebase, idiomatic Rust, and easy Proxmox/Docker deployment
* Security by design: ready for the most demanding blockchain and mesh scenarios

---

## 🔗 Zig Integration

**GhostLink** is fully interoperable with its sister project, [ghostbridge (Zig)](https://github.com/ghostkellz/ghostbridge), which provides the same gRPC interface and protobuf contracts in Zig for even lower-level integrations and high-performance infrastructure nodes.

---

## 📄 License

Licensed under Apache 2.0 by CK Technology LLC, 2025.

