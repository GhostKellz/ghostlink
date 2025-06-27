// ZVM FFI Integration Module
// 
// This module provides Rust bindings for the ZVM (Zig Virtual Machine)
// which handles smart contract execution for GhostChain.

use std::ffi::CStr;
use std::os::raw::c_void;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub mod bindings;
pub mod contract;
pub mod execution;

use bindings::*;

/// ZVM execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub logs: Vec<ExecutionLog>,
    pub error: Option<String>,
}

/// Contract execution log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// ZVM instance wrapper
pub struct ZVM {
    instance: *mut c_void,
}

impl ZVM {
    /// Create a new ZVM instance
    pub fn new() -> Result<Self> {
        unsafe {
            let instance = zvm_create();
            if instance.is_null() {
                return Err(anyhow!("Failed to create ZVM instance"));
            }
            Ok(ZVM { instance })
        }
    }

    /// Execute ZVM native bytecode
    pub fn execute_native(&mut self, bytecode: &[u8], gas_limit: u64) -> Result<ExecutionResult> {
        unsafe {
            let mut result = ZVMResult::default();
            let status = zvm_execute_native(
                self.instance,
                bytecode.as_ptr(),
                bytecode.len(),
                gas_limit,
                &mut result as *mut ZVMResult,
            );

            if status != 0 {
                return Err(anyhow!("ZVM execution failed with status: {}", status));
            }

            Ok(ExecutionResult {
                success: result.success,
                gas_used: result.gas_used,
                return_data: Vec::from_raw_parts(
                    result.return_data,
                    result.return_data_len,
                    result.return_data_len,
                ),
                logs: vec![], // TODO: Parse logs from result
                error: if result.error.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(result.error).to_string_lossy().into_owned())
                },
            })
        }
    }

    /// Execute EVM-compatible bytecode via zEVM layer
    pub fn execute_evm(&mut self, bytecode: &[u8], gas_limit: u64) -> Result<ExecutionResult> {
        unsafe {
            let mut result = ZVMResult::default();
            let status = zvm_execute_evm(
                self.instance,
                bytecode.as_ptr(),
                bytecode.len(),
                gas_limit,
                &mut result as *mut ZVMResult,
            );

            if status != 0 {
                return Err(anyhow!("zEVM execution failed with status: {}", status));
            }

            Ok(ExecutionResult {
                success: result.success,
                gas_used: result.gas_used,
                return_data: Vec::from_raw_parts(
                    result.return_data,
                    result.return_data_len,
                    result.return_data_len,
                ),
                logs: vec![], // TODO: Parse logs from result
                error: if result.error.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(result.error).to_string_lossy().into_owned())
                },
            })
        }
    }

    /// Deploy a new contract
    pub fn deploy_contract(
        &mut self,
        bytecode: &[u8],
        constructor_args: &[u8],
        gas_limit: u64,
    ) -> Result<([u8; 20], ExecutionResult)> {
        unsafe {
            let mut address = [0u8; 20];
            let mut result = ZVMResult::default();
            
            let status = zvm_deploy_contract(
                self.instance,
                bytecode.as_ptr(),
                bytecode.len(),
                constructor_args.as_ptr(),
                constructor_args.len(),
                gas_limit,
                address.as_mut_ptr(),
                &mut result as *mut ZVMResult,
            );

            if status != 0 {
                return Err(anyhow!("Contract deployment failed with status: {}", status));
            }

            let exec_result = ExecutionResult {
                success: result.success,
                gas_used: result.gas_used,
                return_data: Vec::from_raw_parts(
                    result.return_data,
                    result.return_data_len,
                    result.return_data_len,
                ),
                logs: vec![],
                error: if result.error.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(result.error).to_string_lossy().into_owned())
                },
            };

            Ok((address, exec_result))
        }
    }

    /// Call a contract method
    pub fn call_contract(
        &mut self,
        address: &[u8; 20],
        calldata: &[u8],
        gas_limit: u64,
    ) -> Result<ExecutionResult> {
        unsafe {
            let mut result = ZVMResult::default();
            
            let status = zvm_call_contract(
                self.instance,
                address.as_ptr(),
                calldata.as_ptr(),
                calldata.len(),
                gas_limit,
                &mut result as *mut ZVMResult,
            );

            if status != 0 {
                return Err(anyhow!("Contract call failed with status: {}", status));
            }

            Ok(ExecutionResult {
                success: result.success,
                gas_used: result.gas_used,
                return_data: Vec::from_raw_parts(
                    result.return_data,
                    result.return_data_len,
                    result.return_data_len,
                ),
                logs: vec![],
                error: if result.error.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(result.error).to_string_lossy().into_owned())
                },
            })
        }
    }
}

impl Drop for ZVM {
    fn drop(&mut self) {
        unsafe {
            if !self.instance.is_null() {
                zvm_destroy(self.instance);
            }
        }
    }
}

unsafe impl Send for ZVM {}
unsafe impl Sync for ZVM {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zvm_creation() {
        let zvm = ZVM::new();
        assert!(zvm.is_ok());
    }

    #[test]
    fn test_native_execution() {
        let mut zvm = ZVM::new().unwrap();
        
        // Simple ZVM bytecode: PUSH 42, RETURN
        let bytecode = vec![0x01, 42, 0x10]; 
        let result = zvm.execute_native(&bytecode, 1000);
        
        assert!(result.is_ok());
        let exec_result = result.unwrap();
        assert!(exec_result.success);
        assert_eq!(exec_result.return_data, vec![42]);
    }
}
