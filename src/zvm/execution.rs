// ZVM Execution Manager
//
// High-level execution and orchestration for ZVM operations

use super::{ZVM, ExecutionResult, bindings::ZVMContext, contract::*};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

/// ZVM execution environment with state management
pub struct ZVMExecutor {
    zvm: Arc<Mutex<ZVM>>,
    contracts: Arc<RwLock<HashMap<[u8; 20], ContractInfo>>>,
    default_context: ZVMContext,
    #[allow(dead_code)]
    gas_price: u64,
}

impl ZVMExecutor {
    /// Create a new ZVM executor
    pub fn new() -> Result<Self> {
        let zvm = ZVM::new()?;
        Ok(Self {
            zvm: Arc::new(Mutex::new(zvm)),
            contracts: Arc::new(RwLock::new(HashMap::new())),
            default_context: ZVMContext::default(),
            gas_price: 1_000_000_000, // 1 gwei
        })
    }

    /// Update the default execution context
    pub fn set_default_context(&mut self, context: ZVMContext) {
        self.default_context = context;
    }

    /// Deploy a contract with automatic address tracking
    pub async fn deploy_contract(
        &self,
        bytecode: Vec<u8>,
        constructor_args: Vec<u8>,
        gas_limit: Option<u64>,
    ) -> Result<(ContractInfo, ExecutionResult)> {
        let gas_limit = gas_limit.unwrap_or(1_000_000);
        
        info!(
            "Deploying contract with {} bytes of bytecode, gas limit: {}",
            bytecode.len(),
            gas_limit
        );

        let (contract_info, result) = {
            let mut zvm = self.zvm.lock().unwrap();
            let deployer = ContractDeployer::new(&mut zvm, bytecode)
                .with_constructor_args(constructor_args)
                .with_gas_limit(gas_limit)
                .with_context(self.default_context);
            
            deployer.deploy()?
        };

        if result.success {
            info!(
                "Contract deployed successfully at {:?}, gas used: {}",
                hex::encode(contract_info.address),
                result.gas_used
            );
            
            // Store contract info
            let mut contracts = self.contracts.write().await;
            contracts.insert(contract_info.address, contract_info.clone());
        } else {
            error!("Contract deployment failed: {:?}", result.error);
        }

        Ok((contract_info, result))
    }

    /// Call a deployed contract
    pub async fn call_contract(
        &self,
        address: [u8; 20],
        calldata: Vec<u8>,
        gas_limit: Option<u64>,
    ) -> Result<ExecutionResult> {
        let gas_limit = gas_limit.unwrap_or(100_000);
        
        debug!(
            "Calling contract at {:?} with {} bytes of calldata",
            hex::encode(address),
            calldata.len()
        );

        let result = {
            let mut zvm = self.zvm.lock().unwrap();
            let caller = ContractCaller::new(&mut zvm, address)
                .with_raw_calldata(calldata)
                .with_gas_limit(gas_limit)
                .with_context(self.default_context);
            
            caller.call()?
        };

        if result.success {
            debug!(
                "Contract call successful, gas used: {}, return data: {} bytes",
                result.gas_used,
                result.return_data.len()
            );
        } else {
            warn!("Contract call failed: {:?}", result.error);
        }

        Ok(result)
    }

    /// Execute ERC20 token transfer
    pub async fn erc20_transfer(
        &self,
        token_address: [u8; 20],
        to: [u8; 20],
        amount: u64,
        gas_limit: Option<u64>,
    ) -> Result<ExecutionResult> {
        let calldata = ContractUtils::erc20_transfer_call(&to, amount);
        
        info!(
            "ERC20 transfer: {} tokens from {:?} to {:?}",
            amount,
            hex::encode(token_address),
            hex::encode(to)
        );

        self.call_contract(token_address, calldata, gas_limit).await
    }

    /// Get ERC20 token balance
    pub async fn erc20_balance(
        &self,
        token_address: [u8; 20],
        owner: [u8; 20],
    ) -> Result<u64> {
        let calldata = ContractUtils::erc20_balance_call(&owner);
        let result = self.call_contract(token_address, calldata, Some(50_000)).await?;

        if !result.success {
            return Err(anyhow!("Failed to get balance: {:?}", result.error));
        }

        if result.return_data.len() < 32 {
            return Err(anyhow!("Invalid balance response length"));
        }

        ContractUtils::decode_uint256(&result.return_data)
    }

    /// Execute native ZVM bytecode
    pub async fn execute_native(
        &self,
        bytecode: Vec<u8>,
        gas_limit: Option<u64>,
    ) -> Result<ExecutionResult> {
        let gas_limit = gas_limit.unwrap_or(100_000);
        
        debug!(
            "Executing native ZVM bytecode: {} bytes, gas limit: {}",
            bytecode.len(),
            gas_limit
        );

        let result = {
            let mut zvm = self.zvm.lock().unwrap();
            zvm.execute_native(&bytecode, gas_limit)?
        };

        if result.success {
            debug!("Native execution successful, gas used: {}", result.gas_used);
        } else {
            warn!("Native execution failed: {:?}", result.error);
        }

        Ok(result)
    }

    /// Execute EVM-compatible bytecode
    pub async fn execute_evm(
        &self,
        bytecode: Vec<u8>,
        gas_limit: Option<u64>,
    ) -> Result<ExecutionResult> {
        let gas_limit = gas_limit.unwrap_or(100_000);
        
        debug!(
            "Executing EVM bytecode: {} bytes, gas limit: {}",
            bytecode.len(),
            gas_limit
        );

        let result = {
            let mut zvm = self.zvm.lock().unwrap();
            zvm.execute_evm(&bytecode, gas_limit)?
        };

        if result.success {
            debug!("EVM execution successful, gas used: {}", result.gas_used);
        } else {
            warn!("EVM execution failed: {:?}", result.error);
        }

        Ok(result)
    }

    /// Get contract information
    pub async fn get_contract(&self, address: [u8; 20]) -> Option<ContractInfo> {
        let contracts = self.contracts.read().await;
        contracts.get(&address).cloned()
    }

    /// List all deployed contracts
    pub async fn list_contracts(&self) -> Vec<ContractInfo> {
        let contracts = self.contracts.read().await;
        contracts.values().cloned().collect()
    }

    /// Estimate gas for a contract call
    pub async fn estimate_gas(
        &self,
        address: [u8; 20],
        calldata: Vec<u8>,
    ) -> Result<u64> {
        // Try with a high gas limit and see how much is actually used
        let result = self.call_contract(address, calldata, Some(1_000_000)).await?;
        
        if result.success {
            // Add 20% buffer to the actual gas used
            Ok((result.gas_used * 120) / 100)
        } else {
            Err(anyhow!("Gas estimation failed: {:?}", result.error))
        }
    }

    /// Batch execute multiple operations
    pub async fn batch_execute(
        &self,
        operations: Vec<BatchOperation>,
    ) -> Result<Vec<ExecutionResult>> {
        let mut results = Vec::new();
        
        for op in operations {
            let result = match op {
                BatchOperation::ContractCall { address, calldata, gas_limit } => {
                    self.call_contract(address, calldata, gas_limit).await?
                }
                BatchOperation::NativeExecution { bytecode, gas_limit } => {
                    self.execute_native(bytecode, gas_limit).await?
                }
                BatchOperation::EVMExecution { bytecode, gas_limit } => {
                    self.execute_evm(bytecode, gas_limit).await?
                }
            };
            
            results.push(result);
        }
        
        Ok(results)
    }
}

/// Batch operation types for bulk execution
#[derive(Debug, Clone)]
pub enum BatchOperation {
    ContractCall {
        address: [u8; 20],
        calldata: Vec<u8>,
        gas_limit: Option<u64>,
    },
    NativeExecution {
        bytecode: Vec<u8>,
        gas_limit: Option<u64>,
    },
    EVMExecution {
        bytecode: Vec<u8>,
        gas_limit: Option<u64>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_executor_creation() {
        let executor = ZVMExecutor::new();
        assert!(executor.is_ok());
    }

    #[tokio::test]
    async fn test_native_execution() {
        let executor = ZVMExecutor::new().unwrap();
        
        // Simple ZVM bytecode: PUSH 42, RETURN
        let bytecode = vec![0x01, 42, 0x10];
        let result = executor.execute_native(bytecode, Some(1000)).await;
        
        assert!(result.is_ok());
        let exec_result = result.unwrap();
        assert!(exec_result.success);
    }

    #[tokio::test]
    async fn test_contract_tracking() {
        let executor = ZVMExecutor::new().unwrap();
        
        // Deploy a simple contract
        let bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xf3]; // Simple RETURN bytecode
        let result = executor.deploy_contract(bytecode, vec![], Some(100_000)).await;
        
        assert!(result.is_ok());
        let (contract_info, _) = result.unwrap();
        
        // Check if contract is tracked
        let retrieved = executor.get_contract(contract_info.address).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().address, contract_info.address);
    }
}
