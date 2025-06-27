// ZVM FFI Bindings
//
// Raw C bindings for the ZVM (Zig Virtual Machine) library.
// These correspond to the extern "C" functions exported by ZVM.

use std::os::raw::{c_char, c_int, c_void};

/// ZVM execution result from C API
#[repr(C)]
#[derive(Debug)]
pub struct ZVMResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: *mut u8,
    pub return_data_len: usize,
    pub error: *const c_char,
}

impl Default for ZVMResult {
    fn default() -> Self {
        Self {
            success: false,
            gas_used: 0,
            return_data: std::ptr::null_mut(),
            return_data_len: 0,
            error: std::ptr::null(),
        }
    }
}

/// ZVM contract context
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZVMContext {
    pub caller: [u8; 20],
    pub origin: [u8; 20],
    pub gas_price: u64,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub block_hash: [u8; 32],
}

unsafe extern "C" {
    /// Create a new ZVM instance
    pub fn zvm_create() -> *mut c_void;

    /// Destroy a ZVM instance
    pub fn zvm_destroy(instance: *mut c_void);

    /// Execute ZVM native bytecode
    pub fn zvm_execute_native(
        instance: *mut c_void,
        bytecode: *const u8,
        bytecode_len: usize,
        gas_limit: u64,
        result: *mut ZVMResult,
    ) -> c_int;

    /// Execute EVM-compatible bytecode via zEVM
    pub fn zvm_execute_evm(
        instance: *mut c_void,
        bytecode: *const u8,
        bytecode_len: usize,
        gas_limit: u64,
        result: *mut ZVMResult,
    ) -> c_int;

    /// Deploy a contract and return its address
    pub fn zvm_deploy_contract(
        instance: *mut c_void,
        bytecode: *const u8,
        bytecode_len: usize,
        constructor_args: *const u8,
        constructor_args_len: usize,
        gas_limit: u64,
        address_out: *mut u8, // 20-byte address
        result: *mut ZVMResult,
    ) -> c_int;

    /// Call a deployed contract
    pub fn zvm_call_contract(
        instance: *mut c_void,
        address: *const u8, // 20-byte address
        calldata: *const u8,
        calldata_len: usize,
        gas_limit: u64,
        result: *mut ZVMResult,
    ) -> c_int;

    /// Set execution context
    pub fn zvm_set_context(
        instance: *mut c_void,
        context: *const ZVMContext,
    ) -> c_int;

    /// Get contract storage value
    pub fn zvm_get_storage(
        instance: *mut c_void,
        address: *const u8, // 20-byte address
        key: *const u8,     // 32-byte key
        value_out: *mut u8, // 32-byte value
    ) -> c_int;

    /// Set contract storage value
    pub fn zvm_set_storage(
        instance: *mut c_void,
        address: *const u8, // 20-byte address
        key: *const u8,     // 32-byte key
        value: *const u8,   // 32-byte value
    ) -> c_int;

    /// Get account balance
    pub fn zvm_get_balance(
        instance: *mut c_void,
        address: *const u8, // 20-byte address
        balance_out: *mut u64,
    ) -> c_int;

    /// Transfer value between accounts
    pub fn zvm_transfer(
        instance: *mut c_void,
        from: *const u8, // 20-byte address
        to: *const u8,   // 20-byte address
        amount: u64,
    ) -> c_int;

    /// Verify a signature using zsig
    pub fn zvm_verify_signature(
        instance: *mut c_void,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
        public_key_len: usize,
    ) -> c_int;

    /// Resolve a domain name via CNS
    pub fn zvm_resolve_domain(
        instance: *mut c_void,
        domain: *const c_char,
        address_out: *mut u8, // 20-byte address
    ) -> c_int;

    /// Compute Keccak256 hash
    pub fn zvm_keccak256(
        input: *const u8,
        input_len: usize,
        output: *mut u8, // 32-byte output
    ) -> c_int;

    /// Recover public key from ECDSA signature
    pub fn zvm_ecrecover(
        hash: *const u8,      // 32-byte hash
        signature: *const u8, // 65-byte signature (r+s+v)
        public_key_out: *mut u8, // 64-byte uncompressed public key
    ) -> c_int;

    /// Free memory allocated by ZVM
    pub fn zvm_free(ptr: *mut c_void);
}

/// Helper functions for working with ZVM types
impl ZVMContext {
    pub fn new() -> Self {
        Self {
            caller: [0; 20],
            origin: [0; 20],
            gas_price: 1000000000, // 1 gwei default
            block_number: 1,
            block_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            block_hash: [0; 32],
        }
    }

    pub fn with_caller(mut self, caller: [u8; 20]) -> Self {
        self.caller = caller;
        self
    }

    pub fn with_origin(mut self, origin: [u8; 20]) -> Self {
        self.origin = origin;
        self
    }

    pub fn with_gas_price(mut self, gas_price: u64) -> Self {
        self.gas_price = gas_price;
        self
    }

    pub fn with_block_number(mut self, block_number: u64) -> Self {
        self.block_number = block_number;
        self
    }
}

impl Default for ZVMContext {
    fn default() -> Self {
        Self::new()
    }
}
