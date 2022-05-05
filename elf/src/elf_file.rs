extern crate libc;
use super::elf::{ElfAddrType, Elf};

const RT_FULL: usize = 2;
const USER_FULL: usize = 3;

const PAGE_BITS: usize = 12;
const PAGE_SIZE: usize = 1 << PAGE_BITS;

pub struct ElfFile {
    filep: libc::c_int,
    min_vaddr: usize,
    max_vaddr: usize,
    ptr: *mut u8,
    file_size: usize,
    is_runtime: bool,
    elf: Elf,
}

impl ElfFile {
    pub unsafe fn new(filename: &str) -> Self {
        let filep = libc::open(filename.as_ptr() as *const u8, libc::O_RDONLY);

        if filep < 0 {
            panic!("file does not exist - {}", filename);
        }

        let mut stat: libc::stat = std::mem::zeroed();
        let rc = libc::fstat(filep, &mut stat as *mut libc::stat);

        let file_size = if rc == 0 { stat.st_size } else { 0 } as usize;
        if file_size == 0 {
            panic!("invalid file size - {}", filename);
        }

        let ptr = libc::mmap(0 as *mut libc::c_void, file_size.into(), libc::PROT_READ, libc::MAP_PRIVATE, filep, 0);

        if ptr as usize == 0 {
            panic!("mmap failed for {}", filename);
        }

        Self {
            filep,
            min_vaddr: 0,
            max_vaddr: 0,
            ptr: ptr as *mut u8,
            file_size,
            is_runtime: false,
            elf: Elf::new(),
        }
    }

    pub fn get_file_size(&self) -> usize { self.file_size }

    pub fn is_valid(&self) -> bool {
        self.filep > 0 && self.file_size > 0 && self.ptr as usize != 0
    }

    pub fn get_min_vaddr(&self) -> usize { self.min_vaddr }

    pub fn get_total_memory_size(&self) -> usize { self.max_vaddr - self.min_vaddr }

    pub fn initialize(&mut self, is_runtime: bool) -> bool {
        if !self.is_valid() {
            return false;
        }

        if self.elf.new_file(self.ptr, self.file_size) != 0 {
            return false;
        }

        self.elf.get_memory_bounds(ElfAddrType::VIRTUAL, &mut self.min_vaddr, &mut self.max_vaddr);

        if !is_aligned(self.min_vaddr, PAGE_SIZE) {
            return false;
        }

        self.max_vaddr = round_up(self.max_vaddr, PAGE_BITS);
        self.is_runtime = is_runtime;

        true
    }

    pub fn get_page_mode(&self) -> usize {
        if self.is_runtime { RT_FULL } else { USER_FULL }
    }

    pub fn get_num_program_headers(&self) -> usize {
        self.elf.get_num_program_headers()
    }

    pub fn get_program_header_type(&self, ph: usize) -> usize {
        self.elf.get_program_header_type(ph) as usize
    }

    pub fn get_program_header_file_size(&self, ph: usize) -> usize {
        self.elf.get_program_header_file_size(ph) as usize
    }

    pub fn get_program_header_memory_size(&self, ph: usize) -> usize {
        self.elf.get_program_header_memory_size(ph)
    }

    pub fn get_program_header_vaddr(&self, ph: usize) -> usize {
        self.elf.get_program_header_vaddr(ph)
    }

    pub fn get_entry_point(&self) -> usize {
        self.elf.get_entry_point()
    }

    pub fn get_program_segment(&self, ph: usize) -> usize {
        self.elf.get_program_segment(ph) as usize
    }
}

impl Drop for ElfFile {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.filep);
            libc::munmap(self.ptr as *mut libc::c_void, self.file_size.into());
        }
    }
}

#[inline]
pub fn round_up(n: usize, b: usize) -> usize {
    (((n - 1) >> b) + 1) << b
}

#[inline]
pub fn round_down(n: usize, b: usize) -> usize {
    n & !((2 << (b - 1)) - 1)
}

#[inline]
pub fn is_aligned(x: usize, align: usize) -> bool {
    x & (align - 1) != 0
}
