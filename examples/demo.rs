use anyhow::Result;
use ghostlink::{GhostClient, GhostClientConfig};

#[cfg(feature = "zvm-integration")]
use ghostlink::zvm::{ZVMExecutor, contract::ContractUtils};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Initialize GhostLink client
    let config = GhostClientConfig::builder()
        .endpoint("https://ghostbridge.local:9443")
        .with_tls()
        .build();
    
    let mut client = GhostClient::connect(config).await?;
    println!("✅ Connected to GhostBridge");

    // Example 1: Resolve a .ghost domain via ZNS
    println!("\n🌐 Resolving domain via ZNS...");
    match client.zns().resolve_domain("ghostkellz.ghost").await {
        Ok(domain) => println!("Resolved: {:?}", domain),
        Err(e) => println!("Domain resolution failed: {}", e),
    }

    // Example 2: Check wallet balance on GhostChain
    println!("\n💰 Checking wallet balance...");
    let test_address = "ghost1abc123def456ghi789jkl012mno345pqr678stu";
    match client.ghostchain().get_balance(test_address).await {
        Ok(balance) => {
            println!("MANA balance: {}", balance.get("MANA").unwrap_or(&"0".to_string()));
            println!("SPIRIT balance: {}", balance.get("SPIRIT").unwrap_or(&"0".to_string()));
            println!("SOUL balance: {}", balance.get("SOUL").unwrap_or(&"0".to_string()));
        }
        Err(e) => println!("Balance check failed: {}", e),
    }

    // Example 3: ZVM Smart Contract Integration (if feature enabled)
    #[cfg(feature = "zvm-integration")]
    {
        println!("\n🤖 ZVM Smart Contract Operations...");
        
        // Initialize ZVM executor
        let mut zvm_executor = ZVMExecutor::new()?;
        
        // Example: Deploy a simple ERC20 token contract
        let erc20_bytecode = create_simple_erc20_bytecode();
        let constructor_args = encode_erc20_constructor("GhostToken", "GHOST", 1000000);
        
        match zvm_executor.deploy_contract(erc20_bytecode, constructor_args, Some(500_000)).await {
            Ok((contract_info, result)) => {
                println!("✅ ERC20 contract deployed!");
                println!("Address: 0x{}", hex::encode(contract_info.address));
                println!("Gas used: {}", result.gas_used);
                
                // Example: Check token balance
                let balance_call = ContractUtils::erc20_balance_call(&contract_info.address);
                match zvm_executor.call_contract(contract_info.address, balance_call, None).await {
                    Ok(result) => {
                        if result.success && result.return_data.len() >= 32 {
                            let balance = ContractUtils::decode_uint256(&result.return_data)?;
                            println!("Token balance: {}", balance);
                        }
                    }
                    Err(e) => println!("Balance call failed: {}", e),
                }
                
                // Example: Transfer tokens
                let to_address = [0x42u8; 20]; // Example recipient
                let transfer_amount = 1000u64;
                
                match zvm_executor.erc20_transfer(contract_info.address, to_address, transfer_amount, None).await {
                    Ok(result) => {
                        if result.success {
                            println!("✅ Token transfer successful! Gas used: {}", result.gas_used);
                        } else {
                            println!("❌ Token transfer failed: {:?}", result.error);
                        }
                    }
                    Err(e) => println!("Transfer failed: {}", e),
                }
            }
            Err(e) => println!("Contract deployment failed: {}", e),
        }
        
        // Example: Execute native ZVM bytecode
        println!("\n⚡ Native ZVM Execution...");
        let native_bytecode = vec![
            0x01, 42,    // PUSH 42
            0x01, 58,    // PUSH 58  
            0x02,        // ADD
            0x10,        // RETURN
        ];
        
        match zvm_executor.execute_native(native_bytecode, Some(10_000)).await {
            Ok(result) => {
                if result.success {
                    println!("✅ Native execution result: {:?}", result.return_data);
                    println!("Gas used: {}", result.gas_used);
                } else {
                    println!("❌ Native execution failed: {:?}", result.error);
                }
            }
            Err(e) => println!("Native execution error: {}", e),
        }
    }

    // Example 4: Create a GhostID identity
    println!("\n👤 Creating GhostID identity...");
    match client.ghostid().create_identity("example_user", "ed25519_public_key_here").await {
        Ok(identity) => println!("✅ GhostID created: {}", identity.identity_id),
        Err(e) => println!("GhostID creation failed: {}", e),
    }

    println!("\n🎉 GhostLink v0.1.0 demo completed!");
    Ok(())
}

#[cfg(feature = "zvm-integration")]
fn create_simple_erc20_bytecode() -> Vec<u8> {
    // This would be actual EVM bytecode for a simple ERC20 token
    // For demo purposes, using placeholder bytecode
    vec![
        0x60, 0x80, 0x60, 0x40, 0x52, // Contract constructor preamble
        0x60, 0x04, 0x36, 0x10, 0x15, // Function dispatcher
        // ... more EVM bytecode would go here
        0x00, // STOP
    ]
}

#[cfg(feature = "zvm-integration")]
fn encode_erc20_constructor(name: &str, symbol: &str, supply: u64) -> Vec<u8> {
    use ghostlink::zvm::contract::ContractUtils;
    
    // Encode constructor arguments for ERC20(string name, string symbol, uint256 supply)
    let mut args = Vec::new();
    
    // Encode name (simplified - real implementation would use proper ABI encoding)
    args.extend_from_slice(name.as_bytes());
    args.resize(32, 0); // Pad to 32 bytes
    
    // Encode symbol  
    args.extend_from_slice(symbol.as_bytes());
    args.resize(64, 0); // Pad to 32 bytes
    
    // Encode supply
    args.extend_from_slice(&ContractUtils::encode_uint256(supply));
    
    args
}
