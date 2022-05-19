use alloc::rc::Rc;
use core::cell::RefCell;
use crate::common::sha3;
use super::keystone_device::KeystoneDevice;

pub type HashContext = sha3::SHA3;

pub const PTE_V: usize = 0x001;
pub const PTE_R: usize = 0x002;
pub const PTE_W: usize = 0x004;
pub const PTE_X: usize = 0x008;
pub const PTE_U: usize = 0x010;
pub const PTE_G: usize = 0x020;
pub const PTE_A: usize = 0x040;
pub const PTE_D: usize = 0x080;
pub const PTE_SOFT: usize = 0x300;

pub const PTE_PPN_SHIFT: usize = 10;

pub const VA_BITS: usize = if cfg!(feature = "riscv_32") { 32 } else { 39 };
pub const RISCV_PGLEVEL_BITS: usize = if cfg!(feature = "riscv_32") { 10 } else { 9 };

pub const RISCV_PGSHIFT: usize = 12;
pub const RISCV_PGSIZE: usize = 1 << RISCV_PGSHIFT;

pub const RISCV_PGLEVEL_MASK: usize = if cfg!(feature = "riscv_32") { 0x3ff } else { 0x1ff };
pub const RISCV_PGTABLE_HIGHEST_BIT: usize = if cfg!(feature = "riscv_32") { 0x300 } else { 0x100 };

pub const RISCV_PGLEVEL_TOP: usize = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS;

pub trait Memory: Drop {
    fn new() -> Self where Self: Sized;
    fn init(&mut self, dev: Rc<RefCell<dyn KeystoneDevice>>, phys_addr: usize, min_pages: usize);
    fn read_mem(&mut self, src: *const u8, size: usize) -> usize;
    fn write_mem(&mut self, src: *const u8, dst: *mut u8, size: usize);
    fn alloc_mem(&mut self, size: usize) -> usize;
    fn alloc_utm(&mut self, size: usize) -> usize;
    fn alloc_page(&mut self, va: usize, src: *const u8, mode: usize) -> bool;
    fn epm_alloc_vspace(&mut self, addr: usize, num_pages: usize) -> usize;
    fn get_start_addr(&self) -> usize;
    fn get_current_epm_address(&self) -> usize;
    fn get_root_page_table(&self) -> usize;
    fn validate_and_hash_epm(
        &self,
        hash_ctx: &mut HashContext,
        level: isize,
        tb: usize,
        vaddr: usize,
        contiguous: isize,
        runtime_max_seen: &mut usize,
        user_max_seen: &mut usize
    ) -> isize;
    fn start_runtime_mem(&mut self);
    fn start_eapp_mem(&mut self);
    fn start_free_mem(&mut self);
    fn get_runtime_phys_addr(&self) -> usize;
    fn get_eapp_phys_addr(&self) -> usize;
    fn get_free_phys_addr(&self) -> usize;
}
