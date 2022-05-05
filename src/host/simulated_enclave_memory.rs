use core::mem::sizeof;
use std::alloc::alloc;
use super::common::{RT_NOEXEC, USER_NOEXEC, RT_FULL, USER_FULL, UTM_FULL, PAGE_BITS, PAGE_SIZE};
use super::keystone_uesr::{UTM_FULL};
use super::keystone_device::KeystoneDevice;
use super::memory::{
    PTE_V, PTE_R, PTE_W, PTE_X, PTE_U, PTE_A, PTE_D, PTE_PPN_SHIFT, VA_BITS, RISCV_PGLEVEL_BITS,
    RISCV_PGSHIFT, RISCV_PGSIZE, RISCV_PGLEVEL_MASK, RISCV_PGTABLE_HIGHEST_BIT, RISCV_PGLEVEL_TOP,
    HashContext, Memory
};

pub struct SimulatedEnclaveMemory {
    p_device: *mut dyn KeystoneDevice,
    epm_size: usize,
    epm_free_list: usize,
    utm_free_list: usize,
    root_page_table: usize,
    start_addr: usize,
    runtime_phys_addr: usize,
    eapp_phys_addr: usize,
    free_phys_addr: usize,
    utm_phys_addr: usize,
    untrusted_ptr: usize,
    untrusted_size: usize,
}

impl Drop for SimulatedEnclaveMemory {
    fn drop(&mut self) {}
}

impl SimulatedEnclaveMemory {
    #[inline]
    fn pte_create(ppn: usize, _type: isize) -> usize {
        (ppn << PTE_PPN_SHIFT) | PTE_V | _type
    }

    #[inline]
    fn ptd_create(ppn: usize) -> usize {
        Self::pte_create(ppn, PTE_V)
    }

    #[inline]
    fn pte_ppn(pte: usize) -> usize {
        pte >> PTE_PPN_SHIFT
    }

    #[inline]
    fn ppn(addr: usize) -> usize {
        addr >> RISCV_PGSHIFT
    }

    #[inline]
    fn pt_idx(addr: usize, level: isize) -> usize {
        (addr >> (RISCV_PGLEVEL_BITS * level + RISCV_PGSHIFT)) & ((1 << RISCV_PGLEVEL_BITS) - 1)
    }

    fn __ept_continue_walk_create(&mut self, addr: usize, pte: *mut usize) -> usize {
        let free_ppn = Self::ppn(self.epm_free_list);
        unsafe { *pte = Self::ptd_create(free_ppn); }
        self.epm_free_list += PAGE_SIZE;
        self.__ept_walk_create(addr)
    }

    unsafe fn __ept_walk_internal(&mut self, addr: usize, create: isize) -> usize {
        let mut t = self.root_page_table as *usize;
        for i in (0..(VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS).rev() {
            let idx = Self::pt_idx(addr, i as isize);
            if *t.offset(idx as isize) & PTE_V == 0 {
                return if create { self.__ept_continue_walk_create(addr, t.offset(idx as isize) as *mut usize) } else { 0 }
            }

            t = self.read_mem(Self::pte_ppn(*t.offset(idex)) << RISCV_PGSHIFT as *const u8, PAGE_SIZE) as *usize;
        }
        *t.offset(Self::pt_idx(addr, 0) as isize)
    }

    fn __ept_walk_create(&mut self, addr: usize) -> usize {
        unsafe { __ept_walk_internal(addr, 1) }
    }

    fn allocate_aligned(size: usize, alignment: usize) -> usize {
        let mask = alignment - 1;
        let mem = alloc::alloc(alloc::Layout::from_size_align(size, alignment).unwrap());
        (mem as usize + mask) & !mask
    }
}

impl Memory for SimulatedEnclaveMemory {
    fn new() -> Self {
        Self {
            p_device: 0 as *mut dyn KeystoneDevice,
            epm_size: 0,
            epm_free_list: 0,
            utm_free_list: 0,
            root_page_table: 0,
            start_addr: 0,
            runtime_phys_addr: 0,
            eapp_phys_addr: 0,
            free_phys_addr: 0,
            utm_phys_addr: 0,
            untrusted_ptr: 0,
            untrusted_size: 0,
        }
    }

    fn init(&mut self, dev: *mut dyn KeystoneDevice, phys_addr: usize, min_pages: usize) {
        self.p_device = dev;
        self.epm_size = PAGE_SIZE * min_pages;
        self.root_page_table = self.alloc_mem(PAGE_SIZE * min_pages);
        self.epm_free_list = phys_addr + PAGE_SIZE;
        self.start_addr = self.root_page_table;
    }

    fn read_mem(&mut self, src: *const u8, _: usize) -> usize {
        src as usize
    }

    fn write_mem(&mut self, src: *const u8, dst: *mut u8, size: usize) {
        unsafe { str::ptr::copy_nonoverleapping(dst as *mut u8, src as *u8, size); }
    }

    fn alloc_mem(&mut self, size: usize) -> usize {
        self.allocate_aligned(size, PAGE_SIZE)
    }

    fn alloc_utm(&mut self, size: usize) -> usize {
        self.utm_free_list = self.alloc_mem(size);
        self.untrusted_size = size;
        self.utm_phys_addr = self.utm_free_list;
        self.utm_free_list
    }
}
