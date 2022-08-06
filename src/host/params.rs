pub const DEFAULT_STACK_SIZE: usize = if cfg!(feature = "riscv_32") { 1024 * 8 } else { 1024 * 16 };
pub const DEFAULT_STACK_START: usize = if cfg!(feature = "riscv_32") { 0x40000000 } else { 0x0000000040000000 };
pub const DEFAULT_UNTRUSTED_PTR: u64 = if cfg!(feature = "riscv_32") { 0x80000000 } else { 0xffffffff80000000 };
const DEFAULT_UNTRUSTED_SIZE: u64 = 8192;
const DEFAULT_FREEMEM_SIZE: u64 = if cfg!(feature = "riscv_32") { 1024 * 512 } else { 1024 * 1024 };

pub struct Params {
    simulated: bool,
    // runtime_entry: u64,
    // enclave_entry: u64,
    untrusted: u64,
    untrusted_size: u64,
    freemem_size: u64,
}

impl Params {
    pub fn new() -> Self {
        Self {
            simulated: false,
            untrusted: DEFAULT_UNTRUSTED_PTR,
            untrusted_size: DEFAULT_UNTRUSTED_SIZE,
            freemem_size: DEFAULT_FREEMEM_SIZE,
        }
    }

    pub fn set_simulated(&mut self, _simulated: bool) {
        self.simulated = _simulated;
    }

    pub fn set_untrusted_mem(&mut self, ptr: u64, size: u64) {
        self.untrusted = ptr;
        self.untrusted_size = size;
    }

    pub fn set_free_mem_size(&mut self, size: u64) {
        self.freemem_size = size;
    }

    pub fn is_simulated(&self) -> bool {
        self.simulated
    }

    pub fn get_untrusted_mem(&self) -> u64 {
        self.untrusted
    }

    pub fn get_untrusted_size(&self) -> u64 {
        self.untrusted_size
    }

    pub fn get_untrusted_end(&self) -> u64 {
        self.untrusted + self.untrusted_size
    }

    pub fn get_free_mem_size(&self) -> u64 {
        self.freemem_size
    }
}
