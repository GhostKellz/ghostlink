use anyhow::Result;
use clap::{Parser, Subcommand};
use ghostlink::{GhostClient, GhostClientConfig};
use tracing::{info, error};

#[cfg(feature = "zvm-integration")]
use ghostlink::zvm::{ZVMExecutor, contract::ContractUtils};

#[derive(Parser)]
#[command(name = "ghostlink")]
#[command(about = "A Rust gRPC client for GhostChain ecosystem")]
#[command(version)]
struct Cli {
    /// GhostBridge endpoint
    #[arg(short, long, default_value = "https://ghostbridge.local:9443")]
    endpoint: String,
    
    /// Enable TLS
    #[arg(long)]
    tls: bool,
    
    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Domain resolution via ZNS
    Resolve {
        /// Domain to resolve (.ghost, .bc, etc.)
        domain: String,
    },
    /// Check wallet balance on GhostChain
    Balance {
        /// Wallet address
        address: String,
        /// Specific token (MANA, SPIRIT, SOUL)
        #[arg(short, long)]
        token: Option<String>,
    },
    /// Create GhostID identity
    CreateId {
        /// Username
        username: String,
        /// Public key (Ed25519)
        public_key: String,
    },
    /// Smart contract operations (requires zvm-integration feature)
    #[cfg(feature = "zvm-integration")]
    Contract {
        #[command(subcommand)]
        action: ContractCommands,
    },
    /// Execute ZVM bytecode (requires zvm-integration feature)
    #[cfg(feature = "zvm-integration")]
    Execute {
        /// Path to bytecode file
        bytecode_file: String,
        /// Gas limit
        #[arg(short, long, default_value = "100000")]
        gas_limit: u64,
        /// Use EVM compatibility mode
        #[arg(long)]
        evm: bool,
    },
}

#[cfg(feature = "zvm-integration")]
#[derive(Subcommand)]
enum ContractCommands {
    /// Deploy a smart contract
    Deploy {
        /// Path to bytecode file
        bytecode_file: String,
        /// Constructor arguments (hex encoded)
        #[arg(short, long)]
        args: Option<String>,
        /// Gas limit
        #[arg(short, long, default_value = "1000000")]
        gas_limit: u64,
    },
    /// Call a deployed contract
    Call {
        /// Contract address (hex)
        address: String,
        /// Function signature
        function: String,
        /// Function arguments (comma separated)
        #[arg(short, long)]
        args: Option<String>,
        /// Gas limit
        #[arg(short, long, default_value = "100000")]
        gas_limit: u64,
    },
    /// Get ERC20 token balance
    Erc20Balance {
        /// Token contract address (hex)
        token: String,
        /// Owner address (hex)
        owner: String,
    },
    /// Transfer ERC20 tokens
    Erc20Transfer {
        /// Token contract address (hex)
        token: String,
        /// Recipient address (hex)
        to: String,
        /// Amount to transfer
        amount: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    // Create GhostLink client
    info!("Connecting to GhostBridge at {}", cli.endpoint);
    let mut config_builder = GhostClientConfig::builder()
        .endpoint(&cli.endpoint);
    
    if cli.tls {
        config_builder = config_builder.with_tls();
    }
    
    let config = config_builder.build();
    let mut client = GhostClient::connect(config).await?;
    info!("✅ Connected to GhostBridge");

    // Execute command
    match cli.command {
        Commands::Resolve { domain } => {
            info!("Resolving domain: {}", domain);
            match client.zns().resolve_domain(&domain).await {
                Ok(record) => {
                    println!("✅ Domain resolved successfully:");
                    println!("  Domain: {}", record.domain);
                    // Owner information not available in current record structure
                    for dns_record in &record.records {
                        println!("  {}: {}", dns_record.record_type, dns_record.value);
                    }
                    for (chain, address) in &record.addresses {
                        println!("  {} address: {}", chain, address);
                    }
                }
                Err(e) => {
                    error!("❌ Domain resolution failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Balance { address, token } => {
            info!("Checking balance for address: {}", address);
            match client.ghostchain().get_balance(&address).await {
                Ok(balances) => {
                    if let Some(token_name) = token {
                        if let Some(balance) = balances.get(&token_name) {
                            println!("✅ {} balance: {}", token_name, balance);
                        } else {
                            println!("❌ Token '{}' not found", token_name);
                        }
                    } else {
                        println!("✅ Wallet balances:");
                        for (token, balance) in balances {
                            println!("  {}: {}", token, balance);
                        }
                    }
                }
                Err(e) => {
                    error!("❌ Balance check failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::CreateId { username, public_key } => {
            info!("Creating GhostID for user: {}", username);
            match client.ghostid().create_identity(&username, &public_key).await {
                Ok(identity) => {
                    println!("✅ GhostID created successfully:");
                    println!("  Identity ID: {}", identity.identity_id);
                    println!("  Username: {}", identity.username);
                }
                Err(e) => {
                    error!("❌ GhostID creation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        #[cfg(feature = "zvm-integration")]
        Commands::Contract { action } => {
            let mut zvm_executor = ZVMExecutor::new()?;
            
            match action {
                ContractCommands::Deploy { bytecode_file, args, gas_limit } => {
                    info!("Deploying contract from: {}", bytecode_file);
                    let bytecode = std::fs::read(&bytecode_file)?;
                    let constructor_args = if let Some(args) = args {
                        hex::decode(args)?
                    } else {
                        vec![]
                    };
                    
                    match zvm_executor.deploy_contract(bytecode, constructor_args, Some(gas_limit)).await {
                        Ok((contract_info, result)) => {
                            println!("✅ Contract deployed successfully:");
                            println!("  Address: 0x{}", hex::encode(contract_info.address));
                            println!("  Gas used: {}", result.gas_used);
                        }
                        Err(e) => {
                            error!("❌ Contract deployment failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                ContractCommands::Call { address, function, args, gas_limit } => {
                    info!("Calling contract at: {}", address);
                    let contract_address = hex_to_address(&address)?;
                    let selector = ContractUtils::function_selector(&function);
                    let calldata = if let Some(args) = args {
                        [&selector[..], &hex::decode(args)?].concat()
                    } else {
                        selector.to_vec()
                    };
                    
                    match zvm_executor.call_contract(contract_address, calldata, Some(gas_limit)).await {
                        Ok(result) => {
                            println!("✅ Contract call successful:");
                            println!("  Gas used: {}", result.gas_used);
                            println!("  Return data: {}", hex::encode(result.return_data));
                        }
                        Err(e) => {
                            error!("❌ Contract call failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                ContractCommands::Erc20Balance { token, owner } => {
                    let token_address = hex_to_address(&token)?;
                    let owner_address = hex_to_address(&owner)?;
                    
                    match zvm_executor.erc20_balance(token_address, owner_address).await {
                        Ok(balance) => {
                            println!("✅ ERC20 balance: {}", balance);
                        }
                        Err(e) => {
                            error!("❌ Balance check failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                ContractCommands::Erc20Transfer { token, to, amount } => {
                    let token_address = hex_to_address(&token)?;
                    let to_address = hex_to_address(&to)?;
                    
                    match zvm_executor.erc20_transfer(token_address, to_address, amount, None).await {
                        Ok(result) => {
                            if result.success {
                                println!("✅ Transfer successful! Gas used: {}", result.gas_used);
                            } else {
                                println!("❌ Transfer failed: {:?}", result.error);
                            }
                        }
                        Err(e) => {
                            error!("❌ Transfer failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        #[cfg(feature = "zvm-integration")]
        Commands::Execute { bytecode_file, gas_limit, evm } => {
            info!("Executing bytecode from: {}", bytecode_file);
            let bytecode = std::fs::read(&bytecode_file)?;
            let mut zvm_executor = ZVMExecutor::new()?;
            
            let result = if evm {
                zvm_executor.execute_evm(bytecode, Some(gas_limit)).await?
            } else {
                zvm_executor.execute_native(bytecode, Some(gas_limit)).await?
            };
            
            if result.success {
                println!("✅ Execution successful:");
                println!("  Gas used: {}", result.gas_used);
                println!("  Return data: {}", hex::encode(result.return_data));
            } else {
                println!("❌ Execution failed: {:?}", result.error);
            }
        }
    }

    Ok(())
}

#[cfg(feature = "zvm-integration")]
fn hex_to_address(hex_str: &str) -> Result<[u8; 20]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 20 {
        return Err(anyhow::anyhow!("Invalid address length: expected 20 bytes, got {}", bytes.len()));
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    Ok(address)
}
