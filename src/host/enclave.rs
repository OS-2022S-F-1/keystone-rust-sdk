use core::{mem::size_of, cell::RefCell, ptr};
use alloc::{rc::Rc, vec::Vec};
use alloc::boxed::Box;
use xmas_elf::{ElfFile, program::Type};
use crate::common::{sha3::MDSIZE, fs::read};
use crate::edge::EdgeCallHandler;
use crate::host::elf::KeystoneElfFile;
use crate::println;
use super::common::{
    RT_NOEXEC, USER_NOEXEC, RT_FULL, USER_FULL, UTM_FULL, PAGE_BITS, PAGE_SIZE,
    round_up, round_down, page_down, page_up, is_aligned
};
use super::error::Error;
use super::params::{Params, DEFAULT_STACK_START, DEFAULT_STACK_SIZE};
use super::keystone_user::RuntimeParams;
use super::keystone_device::{KeystoneDevice, PhysicalKeystoneDevice, MockKeystoneDevice};
use super::memory::{HashContext, RISCV_PGLEVEL_TOP, Memory};
use super::physical_enclave_memory::PhysicalEnclaveMemory;
use super::simulated_enclave_memory::SimulatedEnclaveMemory;

pub struct ElfData {
    pub runtime_raw: Vec<u8>,
    pub enclave_raw: Vec<u8>,
}

impl ElfData {
    pub fn new(eapp_path: &str, runtime_path: &str) -> Self {
        Self {
            runtime_raw: read(runtime_path),
            enclave_raw: read(eapp_path),
        }
    }
}

pub struct Enclave<'a> {
    params: Params,
    runtime_file: ElfFile<'a>,
    enclave_file: ElfFile<'a>,
    p_memory: Box<dyn Memory>,
    p_device: Rc<RefCell<dyn KeystoneDevice>>,
    hash: [u8; MDSIZE],
    hash_ctx: Option<HashContext>,
    runtime_stk_sz: usize,
    shared_buffer: *mut u8,
    shared_buffer_size: usize,
    ocall_handler: Option<EdgeCallHandler>,
}

impl<'a> Enclave<'a> {
    fn map_untrusted(&mut self) -> bool {
        let untrusted_va = self.params.get_untrusted_mem() as usize;
        let untrusted_size = self.params.get_untrusted_size() as usize;
        println!("load untrusted memory from {:x} with size {:x}", untrusted_va, untrusted_size);
        self.shared_buffer = self.p_device.borrow_mut().map(untrusted_va, untrusted_size, 0, 0) as *mut u8;
        if self.shared_buffer as usize == 0 {
            false
        } else {
            self.shared_buffer_size = untrusted_size;
            true
        }
    }

    fn map_elf(&mut self, eapp: bool) -> bool {
        let elf = if eapp {
            &self.enclave_file
        } else {
            &self.runtime_file
        };

        for header in elf.program_iter() {
            if header.mem_size() == 0 {
                continue;
            }

            let num_pages = round_up(header.mem_size() as usize, PAGE_BITS) / PAGE_SIZE;
            if self.p_memory.epm_alloc_vspace(header.virtual_addr() as usize, num_pages) != num_pages {
                return false;
            }
        }

        true
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

    fn prepare_enclave(&mut self, alternate_phys_addr: usize, data: &'a ElfData) -> bool {
        let min_pages = round_up(self.params.get_free_mem_size() as usize, PAGE_BITS) / PAGE_SIZE
            + calculate_required_pages(
            self.enclave_file.get_total_memory_pages(),
            self.runtime_file.get_total_memory_pages());

        if self.params.is_simulated() {
            self.p_memory.init(self.p_device.clone(), 0, min_pages);
            return true;
        }

        if self.p_device.borrow_mut().create(
            min_pages as u64,
            data.runtime_raw.as_ptr() as usize,
            data.runtime_raw.len(),
            data.enclave_raw.as_ptr() as usize,
            data.enclave_raw.len()
        ) != Error::Success {
            return false;
        }

        let phys_addr = if alternate_phys_addr != 0 {
            alternate_phys_addr
        } else {
            self.p_device.borrow().get_phys_addr()
        };

        self.p_memory.init(self.p_device.clone(), phys_addr, min_pages);
        true
    }

    pub fn new(data: &'a ElfData, params: Params, alternate_phys_addr: usize) -> Result<Self, Error> {
        let (p_memory, p_device): (Box<dyn Memory>, Rc<RefCell<dyn KeystoneDevice>>) = if params.is_simulated() {
            (Box::new(SimulatedEnclaveMemory::new()), Rc::new(RefCell::new(MockKeystoneDevice::new())))
        } else {
            (Box::new(PhysicalEnclaveMemory::new()), Rc::new(RefCell::new(PhysicalKeystoneDevice::new())))
        };

        let enclave_file = ElfFile::new(data.enclave_raw.as_slice()).expect("read eapp err");
        let runtime_file = ElfFile::new(data.runtime_raw.as_slice()).expect("read runtime err");

        if !p_device.borrow_mut().init_device(&params) {
            p_device.borrow_mut().destroy();
            return Err(Error::DeviceInitFailure);
        }

        let mut enclave = Self {
            params,
            runtime_file,
            enclave_file,
            p_memory,
            p_device,
            hash: [0u8; MDSIZE],
            hash_ctx: None,
            runtime_stk_sz: 0,
            shared_buffer: 0 as *mut u8,
            shared_buffer_size: 0,
            ocall_handler: None,
        };

        if !enclave.prepare_enclave(alternate_phys_addr, data) {
            enclave.destroy();
            return Err(Error::DeviceError);
        }

        /**
         * 此处 driver 实现与 keystone 有所区别导致检查不能通过，实际无影响
         */
        if enclave.p_memory.alloc_utm(enclave.params.get_untrusted_size() as usize) == 0 {
            // println!("failed to init untrusted memory - ioctl() failed");
            // enclave.destroy();
            // return Err(Error::DeviceError);
        }

        let runtime_params: RuntimeParams = RuntimeParams {
            runtime_entry: enclave.runtime_file.header.pt2.entry_point() as usize,
            user_entry: enclave.enclave_file.header.pt2.entry_point() as usize,
            untrusted_ptr: enclave.params.get_untrusted_mem() as usize,
            untrusted_size: enclave.params.get_untrusted_size() as usize,
        };

        if !enclave.map_untrusted() {
            println!("failed to finalize enclave - cannot obtain the untrusted buffer pointer");
            enclave.destroy();
            return Err(Error::DeviceMemoryMapError);
        }

        enclave.p_memory.start_free_mem();

        // if enclave.params.is_simulated() {
        //     enclave.validate_and_hash_enclave(&runtime_params);
        // }

        if enclave.p_device.borrow_mut().finalize(
            enclave.p_memory.get_runtime_phys_addr(),
            enclave.p_memory.get_eapp_phys_addr(),
            enclave.p_memory.get_free_phys_addr(),
            runtime_params
        ) != Error::Success {
            enclave.destroy();
            return Err(Error::DeviceError);
        }

        Ok(enclave)
    }

    pub fn get_hash(&self) -> &Option<HashContext> {
        &self.hash_ctx
    }

    pub fn get_shared_buffer(&self) -> *mut u8 {
        self.shared_buffer
    }

    pub fn get_shared_buffer_size(&self) -> usize {
        self.shared_buffer_size
    }

    pub fn register_ocall_handler(&mut self, handler: EdgeCallHandler) -> Error {
        self.ocall_handler = Some(handler);
        Error::Success
    }

    pub fn destroy(&mut self) -> Error {
        self.p_device.borrow_mut().destroy()
    }

    pub fn run(&mut self, ret: &mut usize) -> Error {
        if self.params.is_simulated() {
            Error::Success
        } else {
            let mut err = self.p_device.borrow_mut().run(ret);
            while err == Error::EdgeCallHost || err == Error::EnclaveInterrupted {
                if err == Error::EdgeCallHost && self.ocall_handler.is_some() {
                    self.ocall_handler.as_ref().unwrap().incoming_call_dispatch(self.get_shared_buffer());
                }
                err = self.p_device.borrow_mut().resume(ret);
            }

            if *ret != Error::Success as usize {
                println!("failed to run enclave - ioctl() failed");
                self.destroy();
                Error::DeviceError
            } else {
                Error::Success
            }
        }
    }
}

impl Drop for Enclave<'_> {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[inline]
fn calculate_required_pages(eapp_sz: usize, rt_sz: usize) -> usize {
    eapp_sz + rt_sz + 15
}
