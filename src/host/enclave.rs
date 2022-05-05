use libc;
use core::panicking::panic;
use std::cmp::min;
use std::mem::size_of;
use elf::{ElfFile, PT_LOAD};
use crate::common::sha3::MDSIZE;
use crate::host::keystone_device::PhysicalKeystoneDevice;
use super::common::{
    RT_NOEXEC, USER_NOEXEC, UTM_FULL, PAGE_BITS, PAGE_SIZE,
    round_up, round_down, page_down, page_up, is_aligned
};
use super::error::Error;
use super::params::{DEFAULT_STACK_START, DEFAULT_STACK_SIZE, Params};
use super::keystone_user::RuntimeParams;
use super::keystone_device::{KeystoneDevice, MockKeystoneDevice};
use super::memory::{HashContext, RISCV_PGLEVEL_TOP, Memory};
use super::physical_enclave_memory::PhysicalEnclaveMemory;
use super::simulated_enclave_memory::SimulatedEnclaveMemory;

pub type OCallFunc = fn(_: *mut u8) -> ();

pub struct Enclave {
    params: Params,
    runtime_file: Option<ElfFile>,
    enclave_file: Option<ElfFile>,
    p_memory: *mut dyn Memory,
    p_device: *mut dyn KeystoneDevice,
    hash: [u8; MDSIZE],
    hash_ctx: Option<HashContext>,
    runtime_stk_sz: usize,
    shared_buffer: *mut u8,
    shared_buffer_size: usize,
    o_func_dispatch: Option<OcallFunc>,
}

impl Enclave {
    fn map_untrusted(&mut self, size: usize) -> bool {
        if size == 0 {
            return true;
        }

        self.shared_buffer = self.p_device.map(0, size) as *mut u8;

        if self.shared_buffer as usize == 0 {
            false
        } else {
            self.shared_buffer_size = size;
            true
        }
    }

    fn init_stack(&mut self, start: usize, size: usize, is_rt: bool) -> bool {
        let nullpage = [0u8; PAGE_SIZE];
        let high_addr = round_up(start, PAGE_BITS);
        let mut va_start_stk = round_down(high_addr - size, PAGE_BITS);
        let stk_pages = (high_addr - va_start_stk) / PAGE_SIZE;

        for i in 0..stk_pages {
            if !self.p_memory.allocPage(
                va_start_stk, &nullpage as *[u8],
                if is_rt { RT_NOEXEC } else { USER_NOEXEC }
            ) {
                return false;
            }
            va_start_stk += PAGE_SIZE;
        }
        true
    }

    fn load_untrusted(&mut self) -> Error {
        let mut va_start = round_down(self.params.get_untrusted_mem() as usize, PAGE_BITS);
        let va_end = round_up(self.params.get_untrusted_end() as usize, PAGE_BITS);

        while va_start < va_end {
            if !self.p_memory.alloc_page(va_start, 0 as *const u8, UTM_FULL) {
                return Error::PageAllocationFailure;
            }
            va_start += PAGE_SIZE;
        }
        Error::Success
    }

    fn map_elf(&mut self, elf: &ElfFile) -> bool {
        let num_pages = round_down(elf.get_total_memory_size(), PAGE_BITS) / PAGE_SIZE;
        let va = elf.get_min_vaddr();

        if self.p_memory.epm_alloc_vspace(va, num_pages) != num_pages {
            panic!("failed to allocate vspace");
            false
        } else {
            true
        }
    }

    fn load_elf(&mut self, elf: &ElfFile) -> Error {
        let null_page = [0u8; PAGE_SIZE];
        let mode = elf.get_page_mode();
        for i in elf.get_num_program_headers() {
            if elf.get_program_header_type(i) != PT_LOAD {
                continue
            }

            let start = elf.get_program_header_vaddr(i);
            let file_end = start + elf.get_program_header_file_size(i);
            let memory_end = start + elf.get_program_header_memory_size(i);
            let mut src = elf.get_program_segment(i) as *mut u8;
            let mut va = start;

            if !is_aligned(va, PAGE_SIZE) {
                let offset = va - page_down(va);
                let length = page_up(va) - va;
                let mut page = [0u8; PAGE_SIZE];
                unsafe { libc::memcpy(page.as_mut_ptr().offset(offset as isize), src, length); }
                if !self.p_memory.alloc_page(page_down(va), page.as_ptr(), mode) {
                    return Error::PageAllocationFailure;
                }
                src += length;
                va += length;
            }

            while va + PAGE_SIZE <= file_end {
                if !self.p_memory.alloc_page(va, src, mode) {
                    return Error::PageAllocationFailure;
                }
                src += PAGE_SIZE;
                va += PAGE_SIZE;
            }

            if va < file_end {
                let mut page = [0u8; PAGE_SIZE];
                unsafe { libc::memcpy(page.as_mut_ptr(), src, file_end - va); }
                if !self.p_memory.alloc_page(va, page.as_ptr(), mode) {
                    return Error::PageAllocationFailure;
                }
                va += PAGE_SIZE;
            }

            while va < memory_end {
                if !self.p_memory.alloc_page(va, null_page.as_ptr(), mode) {
                    return Error::PageAllocationFailure;
                }
                va += PAGE_SIZE;
            }
        }

        Error::Success
    }

    fn validate_and_hash_enclave(&mut self, args: &RuntimeParams) -> Error {
        let ptlevel = RISCV_PGLEVEL_TOP;
        let mut hash_ctx = HashContext::new(MDSIZE);

        hash_ctx.sha3_update(&*args as *const RuntimeParams as *const u8, size_of::<RuntimeParams>());

        let mut runtime_max_seen = 0;
        let mut user_max_seen = 0;

        if self.p_memory.validate_and_hash_epm(
            &mut hash_ctx,
            ptlevel as isize,
            self.p_memory.get_root_page_table(),
            0,
            0,
            &mut runtime_max_seen,
            &mut user_max_seen
        ) == -1 {
            Error::InvalidEnclave
        } else {
            hash_ctx.sha3_final(self.hash.as_mut_ptr());
            Error::Success
        }
    }

    fn init_files(&mut self, eapp_path: &str, runtime_path: &str) -> bool {
        if self.enclave_file.is_some() || self.runtime_file.is_some() {
            panic!("ELF files already initialized");
        }

        let mut enclave_file;
        let mut runtime_file;
        unsafe {
            enclave_file = ElfFile::new(eapp_path);
            runtime_file = ElfFile::new(runtime_path);
        }

        if !enclave_file.initialize(true) {
            self.destroy();
            panic!("Invalid enclave ELF");
        }

        if !runtime_path.initialize(true) {
            self.destroy();
            panic!("Invalid runtime ELF");
        }

        if !enclave_file.is_valid() {
            self.destroy();
            panic!("enclave file is not valid");
        }

        if !runtime_path.is_valid() {
            self.destroy();
            panic!("runtime file is not valid");
        }

        self.enclave_file = Some(enclave_file);
        self.runtime_file = Some(runtime_file);

        true
    }

    fn prepare_enclave(&mut self, alternate_phys_addr: usize) -> bool {
        let mut min_pages = round_up(self.params.get_free_mem_size() as usize, PAGE_BITS) / PAGE_SIZE
            + calculate_required_pages(self.enclave_file.as_ref().unwrap().get_total_memory_size(), self.runtime_file.as_ref().unwrap().get_total_memory_size());

        if self.params.is_simulated() {
            self.p_memory.init(0 as *mut dyn KeystoneDevice, 0, min_pages);
            return true;
        }

        if self.p_device.create(min_pages as u64) != Error::Success {
            return false;
        }

        let phys_addr = if alternate_phys_addr != 0 {
            alternate_phys_addr
        } else {
            self.p_device.get_phys_addr()
        };

        self.p_memory.init(self.p_device, phys_addr, min_pages);
        true
    }

    pub fn new() -> Self {
        Self {
            params: Params::new(),
            runtime_file: None,
            enclave_file: None,
            p_memory: 0 as *mut dyn Memory,
            p_device: 0 as *mut dyn KeystoneDevice,
            hash: [0u8; MDSIZE],
            hash_ctx: None,
            runtime_stk_sz: 0,
            shared_buffer: 0 as *mut u8,
            shared_buffer_size: 0,
            o_func_dispatch: None,
        }
    }

    pub fn get_hash(&self) -> &Option<HashContext> {
        &self.hash_ctx
    }

    pub fn get_shared_buffer(&mut self) -> *mut u8 {
        self.shared_buffer
    }

    pub fn get_shared_buffer_size(&self) -> usize {
        self.shared_buffer_size
    }

    pub fn register_ocall_dispatch(&mut self, func: OCallFunc) -> Error {
        self.o_func_dispatch = Some(func);
        Error::Success
    }

    pub fn init(&mut self, eapp_path: &str, runtime_path: &str, params: Params, alternate_phys_addr: usize) -> Error {
        if self.params.is_simulated() {
            self.p_memory = &SimulatedEnclaveMemory::new() as *mut SimulatedEnclaveMemory;
            self.p_device = &MockKeystoneDevice::new() as *mut MockKeystoneDevice;
        } else {
            self.p_memory = &PhysicalEnclaveMemory::new() as *mut PhysicalEnclaveMemory;
            self.p_device = &PhysicalKeystoneDevice::new() as *mut PhysicalKeystoneDevice;
        }

        if !self.init_files(eapp_path, runtime_path) {
            return Error::FileInitFailure;
        }

        if !self.p_device.init_device(&params) {
            self.destroy();
            return Error::DeviceInitFailure;
        }

        if !self.prepare_enclave(alternate_phys_addr) {
            self.destroy();
            return Error::DeviceError;
        }

        if !self.map_elf(self.runtime_file.as_ref().unwrap()) {
            self.destroy();
            return Error::VSpaceAllocationFailure;
        }

        self.p_memory.start_runtime_mem();

        if self.load_elf(self.runtime_file.as_ref().unwrap()) != Error::Success {
            println!("failed to load runtime ELF");
            self.destroy();
            return Error::ELFLoadFailure;
        }

        if !self.map_elf(self.enclave_file.as_ref().unwrap()) {
            self.destroy();
            return Error::VSpaceAllocationFailure;
        }

        self.p_memory.start_eapp_mem();

        if self.load_elf(self.enclave_file.as_ref().unwrap()) != Error::Success {
            println!("failed to load enclave ELF");
            self.destroy();
            return Error::ELFLoadFailure;
        }

        #[cfg(use_freemem)]
        if !self.init_stack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0) {
            println!("failed to init static stack");
            self.destroy();
            return Error::PageAllocationFailure;
        }

        if !self.p_memory.alloc_utm(params.get_untrusted_size() as usize) {
            println!("failed to init untrusted memory - ioctl() failed");
            self.destroy();
            return Error::DeviceError;
        }

        if self.load_untrusted() != Error::Success {
            println!("failed to load untrusted");
        }

        let runtime_params: RuntimeParams = RuntimeParams {
            runtime_entry: self.runtime_file.as_ref().unwrap().get_entry_point(),
            user_entry: self.enclave_file.as_ref().unwrap().get_entry_point(),
            untrusted_ptr: params.get_untrusted_mem() as usize,
            untrusted_size: params.get_untrusted_size() as usize,
        };

        self.p_memory.start_free_mem();

        if params.is_simulated() {
            self.validate_and_hash_enclave(&runtime_params);
        }

        if self.p_device.finalize(
            self.p_memory.get_runtime_phys_addr(),
            self.p_memory.get_eapp_phys_addr(),
            self.p_memory.get_free_phys_addr()
        ) != Error::Success {
            self.destroy();
            return Error::DeviceError;
        }

        if !self.map_untrusted(params.get_untrusted_size() as usize) {
            println!("failed to finalize enclave - cannot obtain the untrusted buffer pointer");
            self.destroy();
            return Error::DeviceMemoryMapError;
        }

        self.enclave_file.take();
        self.runtime_file.take();
        self.params = params;
        Error::Success
    }

    pub fn destroy(&mut self) -> Error {
        self.runtime_file.take();
        self.enclave_file.take();
        self.p_device.destroy()
    }

    pub fn run(&mut self, ret: &mut usize) -> Error {
        if self.params.is_simulated() {
            Error::Success
        } else {
            let mut err = self.p_device.run(ret);
            while err == Error::EdgeCallHost || err == Error::EnclaveInterrupted {
                if err == Error::EdgeCallHost && self.o_func_dispatch.is_some() {
                    self.o_func_dispatch.unwrap()(self.get_shared_buffer());
                }
                err = self.p_device.resume(ret);
            }

            if ret != Error::Success {
                println!("failed to run enclave - ioctl() failed");
                self.destroy();
                Error::DeviceError
            } else {
                Error::Success
            }
        }
    }
}

impl Drop for Enclave {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[inline]
fn calculate_required_pages(eapp_sz: usize, rt_sz: usize) -> usize {
    // ceil(eapp_sz / PAGE_SIZE) + ceil(rt_sz / PAGE_SIZE) + 15
    eapp_sz / PAGE_SIZE + rt_sz / PAGE_SIZE + 15
}
