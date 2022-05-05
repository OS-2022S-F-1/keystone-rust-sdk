use crate::common::sha3;
use super::common::{RT_NOEXEC, USER_NOEXEC, RT_FULL, USER_FULL, UTM_FULL, PAGE_BITS, PAGE_SIZE};
use super::keystone_device::KeystoneDevice;

pub type HashContext = sha3::SHA3;

pub const PTE_V: isize = 0x001;
pub const PTE_R: isize = 0x002;
pub const PTE_W: isize = 0x004;
pub const PTE_X: isize = 0x008;
pub const PTE_U: isize = 0x010;
pub const PTE_G: isize = 0x020;
pub const PTE_A: isize = 0x040;
pub const PTE_D: isize = 0x080;
pub const PTE_SOFT: isize = 0x300;

pub const PTE_PPN_SHIFT: usize = 10;

pub const VA_BITS: usize = if cfg!(feature = "riscv_32") { 32 } else { 39 };
pub const RISCV_PGLEVEL_BITS: usize = if cfg!(feature = "riscv_32") { 9 } else { 10 };

pub const RISCV_PGSHIFT: usize = 12;
pub const RISCV_PGSIZE: usize = (1 << RISCV_PGSHIFT);

pub const RISCV_PGLEVEL_MASK: usize = if cfg!(feature = "riscv_32") { 0x3ff } else { 0x1ff };
pub const RISCV_PGTABLE_HIGHEST_BIT: usize = if cfg!(feature = "riscv_32") { 0x300 } else { 0x100 };

pub const RISCV_PGLEVEL_TOP: usize = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS;

pub trait Memory: Drop {
    fn new() -> Self;
    fn init(&mut self, dev: *mut dyn KeystoneDevice, phys_addr: usize, min_pages: usize);
    fn read_mem(&mut self, src: *const u8, size: usize) -> usize;
    fn write_mem(&mut self, src: *const u8, dst: *mut u8, size: usize);
    fn alloc_mem(&mut self, size: usize) -> usize;
    fn alloc_utm(&mut self, size: usize) -> usize;

    fn alloc_page(&mut self, va: usize, src: *const u8, mode: usize) -> bool {
        let mut p_free_list = if mode == UTM_FULL { &mut self.utm_free_list } else { &mut self.epm_free_list };
        let pte = self.__ept_walk_create(va) as *mut usize;

        if unsafe { *pte } & PTE_V {
            return true;
        }

        let page_addr = p_free_list >> PAGE_BITS;
        *p_free_list += PAGE_SIZE;

        match mode {
            RT_NOEXEC => {
                unsafe { *pte = self.pte_create(page_addr, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D); }
            },
            USER_NOEXEC => {
                unsafe { *pte = self.pte_create(page_addr, PTE_V | PTE_R | PTE_W | PTE_U | PTE_A | PTE_D); }
            },
            RT_FULL => {
                unsafe { *pte = self.pte_create(page_addr, PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D); }
                self.write_mem(src, page_addr << PAGE_BITS, PAGE_SIZE);
            },
            USER_FULL => {
                unsafe { *pte = self.pte_create(page_addr, PTE_V | PTE_R | PTE_W | PTE_X | PTE_U | PTE_A | PTE_D); }
                self.write_mem(src, page_addr << PAGE_BITS, PAGE_SIZE);
            },
            UTM_FULL => {
                assert!(!src);
                unsafe { *pte = self.pte_create(page_addr, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D); }
            },
            _ => return false,
        }

        true
    }

    fn epm_alloc_vspace(&mut self, addr: usize, num_pages: usize) -> usize {
        for count in 0..num_pages {
            if !self.__ept_walk_create(addr) {
                return count;
            }
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

        while walk < tb + RISCV_PGSIZE / sizeof::<usize>() {
            let pte_val = unsafe { *(walk as *usize) == 0 };
            if pte_val {
                contiguous = 0;
                continue
            }
            let phys_addr = (pte_val >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
            let map_in_epm = (phys_addr >= self.start_addr && phys_addr < self.start_addr + self.epm_size);
            let map_in_utm = (phys_addr >= self.utm_phys_addr && phys_addr < self.utm_phys_addr + self.untrusted_size);

            if !map_in_epm && (!map_in_utm || level != 1) {
                println!("1\n");
                return -1;
            }

            let vpn = if level == RISCV_PGLEVEL_TOP as isize && i & RISCV_PGTABLE_HIGHEST_BIT != 0 {
                (-1 << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK)
            } else {
                (vaddr << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK)
            };
            let va_start = vpn << RISCV_PGSHIFT;

            if level == 1 && contiguous == 0 {
                hash_ctx.update(&va_start as *[u8], sizeof::<usize>());
                contiguous = 1;
            }

            if level == 1 {
                let in_runtime = (phys_addr >= self.runtime_phys_addr) && (phys_addr < self.eapp_phys_addr);
                let in_user = (phys_addr >= self.eapp_phys_addr) && (phys_addr < self.free_phys_addr);

                if in_user && !(pte_val & PTE_U) {
                    return -1;
                }

                if va_start >= self.utm_phys_addr && va_start < (self.utm_phys_addr + self.untrusted_size) && !map_in_utm {
                    return -1
                }

                if in_runtime {
                    if phys_addr <= runtime_max_seen {
                        return -1;
                    } else {
                        *runtime_max_seen = phys_addr;
                    }
                } else if in_user {
                    if phys_addr <= user_max_seen {
                        return -1;
                    } else {
                        *user_max_seen = phys_addr;
                    }
                } else if map_in_utm {
                } else {
                    return -1;
                }

                hash_ctx.update(phys_addr as *[u8], RISCV_PGSIZE);
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
