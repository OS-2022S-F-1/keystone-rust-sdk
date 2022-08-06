use core::{ptr, mem::size_of, cell::RefCell};
use alloc::rc::Rc;
use crate::println;
use super::common::{RT_NOEXEC, USER_NOEXEC, RT_FULL, USER_FULL, UTM_FULL, PAGE_BITS, PAGE_SIZE};
use super::keystone_device::KeystoneDevice;
use super::memory::{
    PTE_V, PTE_R, PTE_W, PTE_X, PTE_U, PTE_A, PTE_D, PTE_PPN_SHIFT, VA_BITS, RISCV_PGLEVEL_BITS,
    RISCV_PGSHIFT, RISCV_PGSIZE, RISCV_PGLEVEL_MASK, RISCV_PGTABLE_HIGHEST_BIT, RISCV_PGLEVEL_TOP,
    HashContext, Memory
};

pub struct PhysicalEnclaveMemory {
    p_device: Option<Rc<RefCell<dyn KeystoneDevice>>>,
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

impl Drop for PhysicalEnclaveMemory {
    fn drop(&mut self) {}
}

impl PhysicalEnclaveMemory {
    #[inline]
    fn pte_create(ppn: usize, _type: isize) -> usize {
        (ppn << PTE_PPN_SHIFT) | PTE_V | _type as usize
    }

    #[inline]
    fn ptd_create(ppn: usize) -> usize {
        Self::pte_create(ppn, PTE_V as isize)
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
    fn pt_idx(addr: usize, level: usize) -> usize {
        (addr >> (RISCV_PGLEVEL_BITS * level + RISCV_PGSHIFT)) & ((1 << RISCV_PGLEVEL_BITS) - 1)
    }

    fn __ept_continue_walk_create(&mut self, mut t: *mut usize, addr: usize, pte: *mut usize, skip: usize) -> usize {
        let free_ppn = Self::ppn(self.epm_free_list);
        unsafe { *pte = Self::ptd_create(free_ppn); }
        self.epm_free_list += PAGE_SIZE;
        self.__ept_walk_create(t, addr, skip)
    }

    unsafe fn __ept_walk_internal(&mut self, mut t: *mut usize, addr: usize, create: bool, skip: usize) -> usize {
        for i in (1..=(VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - skip).rev() {
            let idx = Self::pt_idx(addr, i);
            let ptr = t.offset(idx as isize);
            if *ptr & PTE_V == 0 {
                return if create {
                    self.__ept_continue_walk_create(t, addr, ptr as *mut usize, (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - i)
                } else {
                    0
                };
            }

            t = self.read_mem((Self::pte_ppn(*ptr) << RISCV_PGSHIFT) as *const u8, PAGE_SIZE) as *mut usize;
        }
        t.offset(Self::pt_idx(addr, 0) as isize) as usize
    }

    fn __ept_walk_create(&mut self, mut t: *mut usize, addr: usize, skip: usize) -> usize {
        unsafe { self.__ept_walk_internal(t, addr, true, skip) }
    }
}

impl Memory for PhysicalEnclaveMemory {
    fn new() -> Self {
        Self {
            p_device: None,
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

    fn init(&mut self, dev: Rc<RefCell<dyn KeystoneDevice>>, phys_addr: usize, min_pages: usize) {
        self.p_device = Some(dev);
        self.epm_size = PAGE_SIZE * min_pages;
        // self.root_page_table = self.alloc_mem(PAGE_SIZE);
        // for i in 0..PAGE_SIZE {
        //     unsafe {
        //         *(self.root_page_table as *mut u8).offset(i as isize) = 0u8;
        //     }
        // }
        self.epm_free_list = phys_addr + PAGE_SIZE;
        self.start_addr = phys_addr;
    }

    fn read_mem(&mut self, src: *const u8, size: usize) -> usize {
        assert!(self.p_device.is_some());
        self.p_device.as_ref().unwrap().borrow_mut().map(0, size, 0, src as usize - self.start_addr) as usize
    }

    fn write_mem(&mut self, va: usize, src: *const u8, dst: *mut u8, size: usize) {
        assert!(self.p_device.is_some());
        let va_dst = self.p_device.as_ref().unwrap().borrow_mut().map(va, size, 0, unsafe { dst.offset(-(self.start_addr as isize)) as usize });
        unsafe { ptr::copy_nonoverlapping(src, va_dst as *mut u8, size); }
    }

    fn alloc_mem(&mut self, _size: usize) -> usize {
        assert!(self.p_device.is_some());
        self.p_device.as_ref().unwrap().borrow_mut().map(0, PAGE_SIZE, 0, 0) as usize
    }

    fn alloc_utm(&mut self, size: usize) -> usize {
        assert!(self.p_device.is_some());
        let ret = self.p_device.as_ref().unwrap().borrow_mut().init_utm(size);
        self.utm_free_list = ret;
        self.untrusted_size = size;
        self.utm_phys_addr = ret;
        ret
    }

    fn alloc_page(&mut self, va: usize, size: usize) -> bool {
        self.p_device.as_ref().unwrap().borrow_mut().map(va, size, 0, 0);
        true
    }

    fn epm_alloc_vspace(&mut self, mut addr: usize, num_pages: usize) -> usize {
        for count in 0..num_pages {
            if self.__ept_walk_create(self.root_page_table as *mut usize, addr, 0) == 0 {
                return count;
            }
            addr += PAGE_SIZE;
        }
        num_pages
    }

    fn get_start_addr(&self) -> usize {
        self.start_addr
    }

    fn get_current_epm_address(&self) -> usize {
        self.epm_free_list
    }

    fn get_root_page_table(&self) -> usize {
        self.root_page_table
    }

    fn validate_and_hash_epm(
        &self,
        hash_ctx: &mut HashContext,
        level: isize,
        tb: usize,
        vaddr: usize,
        mut contiguous: isize,
        runtime_max_seen: &mut usize,
        user_max_seen: &mut usize
    ) -> isize {
        let mut walk = tb;
        let mut i = 0;

        while walk < tb + RISCV_PGSIZE / size_of::<usize>() {
            let pte_val = unsafe { *(walk as *const usize) };
            if pte_val == 0 {
                contiguous = 0;
                continue
            }
            let phys_addr = (pte_val >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
            let map_in_epm = phys_addr >= self.start_addr && phys_addr < self.start_addr + self.epm_size;
            let map_in_utm = phys_addr >= self.utm_phys_addr && phys_addr < self.utm_phys_addr + self.untrusted_size;

            if !map_in_epm && (!map_in_utm || level != 1) {
                return -1;
            }

            let vpn = if level == RISCV_PGLEVEL_TOP as isize && i & RISCV_PGTABLE_HIGHEST_BIT != 0 {
                (!0 << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK)
            } else {
                (vaddr << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK)
            };
            let va_start = vpn << RISCV_PGSHIFT;

            if level == 1 && contiguous == 0 {
                hash_ctx.sha3_update(&va_start as *const usize as *const u8, size_of::<usize>());
                contiguous = 1;
            }

            if level == 1 {
                let in_runtime = (phys_addr >= self.runtime_phys_addr) && (phys_addr < self.eapp_phys_addr);
                let in_user = (phys_addr >= self.eapp_phys_addr) && (phys_addr < self.free_phys_addr);

                if in_user && pte_val & PTE_U == 0 {
                    return -1;
                }

                if va_start >= self.utm_phys_addr && va_start < (self.utm_phys_addr + self.untrusted_size) && !map_in_utm {
                    return -1
                }

                if in_runtime {
                    if phys_addr <= *runtime_max_seen {
                        return -1;
                    } else {
                        *runtime_max_seen = phys_addr;
                    }
                } else if in_user {
                    if phys_addr <= *user_max_seen {
                        return -1;
                    } else {
                        *user_max_seen = phys_addr;
                    }
                } else if map_in_utm {
                } else {
                    return -1;
                }

                hash_ctx.sha3_update(phys_addr as *const u8, RISCV_PGSIZE);
            } else {
                contiguous = self.validate_and_hash_epm(
                    hash_ctx,
                    level - 1,
                    phys_addr,
                    vpn,
                    contiguous,
                    runtime_max_seen,
                    user_max_seen
                );
                if contiguous == -1 {
                    println!("BAD MAP: {}->{} epm {} {} uer {} {}\n",
                             va_start, phys_addr, 0, self.runtime_phys_addr, 0, self.eapp_phys_addr);
                    return -1;
                }
            }

            walk += 1;
            i += 1;
        }

        contiguous
    }

    fn start_runtime_mem(&mut self) {
        self.runtime_phys_addr = self.get_current_epm_address();
    }

    fn start_eapp_mem(&mut self) {
        self.eapp_phys_addr = self.get_current_epm_address();
    }

    fn start_free_mem(&mut self) {
        self.free_phys_addr = self.get_current_epm_address();
    }

    fn get_runtime_phys_addr(&self) -> usize {
        self.runtime_phys_addr
    }

    fn get_eapp_phys_addr(&self) -> usize {
        self.eapp_phys_addr
    }

    fn get_free_phys_addr(&self) -> usize {
        self.free_phys_addr
    }
}
