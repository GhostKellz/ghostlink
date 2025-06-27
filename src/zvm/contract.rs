// ZVM Contract Utilities
//
// High-level utilities for working with smart contracts in ZVM

use super::{ZVM, ExecutionResult, bindings::ZVMContext};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Smart contract metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    pub address: [u8; 20],
    pub bytecode: Vec<u8>,
    pub abi: Option<ContractABI>,
    pub constructor_args: Vec<u8>,
    pub deployed_at: u64,
}

/// Simple ABI representation for contract interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractABI {
    pub functions: HashMap<String, FunctionSignature>,
    pub events: HashMap<String, EventSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub inputs: Vec<ABIParam>,
    pub outputs: Vec<ABIParam>,
    pub selector: [u8; 4], // Function selector (first 4 bytes of keccak256(signature))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSignature {
    pub name: String,
    pub inputs: Vec<ABIParam>,
    pub topic: [u8; 32], // Event topic (keccak256 of signature)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIParam {
    pub name: String,
    pub param_type: String, // "uint256", "address", "bytes", etc.
    pub indexed: bool, // For events only
}

/// Contract deployment builder
pub struct ContractDeployer<'a> {
    zvm: &'a mut ZVM,
    bytecode: Vec<u8>,
    constructor_args: Vec<u8>,
    gas_limit: u64,
    context: ZVMContext,
}

impl<'a> ContractDeployer<'a> {
    pub fn new(zvm: &'a mut ZVM, bytecode: Vec<u8>) -> Self {
        Self {
            zvm,
            bytecode,
            constructor_args: Vec::new(),
            gas_limit: 1_000_000, // Default gas limit
            context: ZVMContext::default(),
        }
    }

    pub fn with_constructor_args(mut self, args: Vec<u8>) -> Self {
        self.constructor_args = args;
        self
    }

    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    pub fn with_context(mut self, context: ZVMContext) -> Self {
        self.context = context;
        self
    }

    pub fn deploy(self) -> Result<(ContractInfo, ExecutionResult)> {
        let (address, result) = self.zvm.deploy_contract(
            &self.bytecode,
            &self.constructor_args,
            self.gas_limit,
        )?;

        let contract_info = ContractInfo {
            address,
            bytecode: self.bytecode,
            abi: None, // TODO: Parse from metadata
            constructor_args: self.constructor_args,
            deployed_at: self.context.block_number,
        };

        Ok((contract_info, result))
    }
}

/// Contract call builder
pub struct ContractCaller<'a> {
    zvm: &'a mut ZVM,
    address: [u8; 20],
    calldata: Vec<u8>,
    gas_limit: u64,
    context: ZVMContext,
}

impl<'a> ContractCaller<'a> {
    pub fn new(zvm: &'a mut ZVM, address: [u8; 20]) -> Self {
        Self {
            zvm,
            address,
            calldata: Vec::new(),
            gas_limit: 100_000,
            context: ZVMContext::default(),
        }
    }

    pub fn with_function_call(mut self, selector: [u8; 4], args: &[u8]) -> Self {
        self.calldata = [&selector[..], args].concat();
        self
    }

    pub fn with_raw_calldata(mut self, calldata: Vec<u8>) -> Self {
        self.calldata = calldata;
        self
    }

    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    pub fn with_context(mut self, context: ZVMContext) -> Self {
        self.context = context;
        self
    }

    pub fn call(self) -> Result<ExecutionResult> {
        self.zvm.call_contract(&self.address, &self.calldata, self.gas_limit)
    }
}

/// Utility functions for contract interaction
pub struct ContractUtils;

impl ContractUtils {
    /// Calculate function selector from signature
    /// Example: "transfer(address,uint256)" -> [0xa9, 0x05, 0x9c, 0xbb]
    pub fn function_selector(signature: &str) -> [u8; 4] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(signature.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Calculate event topic from signature
    /// Example: "Transfer(address,address,uint256)" -> 32-byte hash
    pub fn event_topic(signature: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(signature.as_bytes());
        hash.into()
    }

    /// Encode uint256 for ABI
    pub fn encode_uint256(value: u64) -> Vec<u8> {
        let mut encoded = vec![0u8; 32];
        encoded[24..32].copy_from_slice(&value.to_be_bytes());
        encoded
    }

    /// Encode address for ABI (20 bytes, left-padded to 32 bytes)
    pub fn encode_address(address: &[u8; 20]) -> Vec<u8> {
        let mut encoded = vec![0u8; 32];
        encoded[12..32].copy_from_slice(address);
        encoded
    }

    /// Decode uint256 from ABI
    pub fn decode_uint256(data: &[u8]) -> Result<u64> {
        if data.len() < 32 {
            return Err(anyhow!("Invalid uint256 data length"));
        }
        
        let bytes: [u8; 8] = data[24..32].try_into()
            .map_err(|_| anyhow!("Failed to extract uint256 bytes"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Decode address from ABI
    pub fn decode_address(data: &[u8]) -> Result<[u8; 20]> {
        if data.len() < 32 {
            return Err(anyhow!("Invalid address data length"));
        }
        
        let address: [u8; 20] = data[12..32].try_into()
            .map_err(|_| anyhow!("Failed to extract address bytes"))?;
        Ok(address)
    }

    /// Create a simple ERC20 transfer call
    pub fn erc20_transfer_call(to: &[u8; 20], amount: u64) -> Vec<u8> {
        let selector = Self::function_selector("transfer(address,uint256)");
        let to_encoded = Self::encode_address(to);
        let amount_encoded = Self::encode_uint256(amount);
        
        [&selector[..], &to_encoded, &amount_encoded].concat()
    }

    /// Create a simple ERC20 balanceOf call
    pub fn erc20_balance_call(address: &[u8; 20]) -> Vec<u8> {
        let selector = Self::function_selector("balanceOf(address)");
        let address_encoded = Self::encode_address(address);
        
        [&selector[..], &address_encoded].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_selector() {
        let selector = ContractUtils::function_selector("transfer(address,uint256)");
        // This should match the known ERC20 transfer selector
        assert_eq!(selector, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_encode_decode_uint256() {
        let value = 1000u64;
        let encoded = ContractUtils::encode_uint256(value);
        let decoded = ContractUtils::decode_uint256(&encoded).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_encode_decode_address() {
        let address = [1u8; 20];
        let encoded = ContractUtils::encode_address(&address);
        let decoded = ContractUtils::decode_address(&encoded).unwrap();
        assert_eq!(address, decoded);
    }

    #[test]
    fn test_erc20_calls() {
        let to_address = [0x42u8; 20];
        let amount = 1000u64;
        
        let transfer_call = ContractUtils::erc20_transfer_call(&to_address, amount);
        assert!(transfer_call.len() > 4); // Should have selector + args
        
        let balance_call = ContractUtils::erc20_balance_call(&to_address);
        assert!(balance_call.len() > 4); // Should have selector + args
    }
}
