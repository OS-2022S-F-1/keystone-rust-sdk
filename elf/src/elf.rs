extern crate libc;
use std::mem::size_of;

const ELFMAG: &str = "OELF";
const SELFMAG: usize = 4;

const EI_CLASS: usize = 4;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

const SHT_STRTAB: usize = 3;

pub const PT_LOAD: usize = 1;

pub struct Elf {
    elf_file: *const u8,
    elf_size: usize,
    elf_class: u8,
}

#[derive(PartialEq)]
pub enum ElfAddrType {
    VIRTUAL,
    PHYSICAL,
}

// elf32
impl Elf {
    fn elf32_check_file(&mut self) -> isize {
        if  self.elf_size < size_of::<libc::Elf32_Ehdr>() ||
            self.check_magic() < 0 {
            return -1;
        }

        let header = self.elf32_get_header();
        if  header.e_ident[EI_CLASS] != ELFCLASS32 ||
            header.e_ident[EI_CLASS] as usize != size_of::<libc::Elf32_Phdr>() ||
            header.e_shentsize as usize != size_of::<libc::Elf32_Shdr>() ||
            header.e_shstrndx >= header.e_shnum {
            return -1;
        }

        self.elf_class = header.e_ident[EI_CLASS];
        0
    }

    fn elf32_check_program_header_table(&self) -> isize {
        let header = self.elf32_get_header();
        let ph_end = header.e_phoff + (header.e_phentsize * header.e_phnum) as u32;
        if self.elf_size < ph_end as usize || ph_end < header.e_phoff {
            -1
        } else {
            0
        }
    }

    fn elf32_check_section_table(&self) -> isize {
        let header = self.elf32_get_header();
        let sh_end = header.e_shoff + (header.e_shentsize * header.e_shnum) as u32;
        if self.elf_size < sh_end as usize || sh_end < header.e_shoff {
            -1
        } else {
            0
        }
    }

    #[inline]
    fn is_elf32(&self) -> bool {
        self.elf_class == ELFCLASS32
    }

    #[inline]
    fn elf32_get_header(&self) -> &libc::Elf32_Ehdr {
        unsafe { &*(self.elf_file as *const libc::Elf32_Ehdr) }
    }

    #[inline]
    fn elf32_get_entry_point(&self) -> u32 {
        self.elf32_get_header().e_entry
    }

    #[inline]
    fn elf32_get_program_header_table(&self) -> *const libc::Elf32_Phdr {
        unsafe { self.elf_file.offset(self.elf32_get_header().e_phoff as isize) as *const libc::Elf32_Phdr }
    }

    #[inline]
    fn elf32_get_program_header_table_offset(&self, offset: isize) -> &libc::Elf32_Phdr {
        unsafe { &*self.elf32_get_program_header_table().offset(offset) }
    }

    #[inline]
    fn elf32_get_section_table(&self) -> *const libc::Elf32_Shdr {
        unsafe { self.elf_file.offset(self.elf32_get_header().e_shoff as isize) as *const libc::Elf32_Shdr }
    }

    #[inline]
    fn elf32_get_section_table_offset(&self, offset: isize) -> &libc::Elf32_Shdr {
        unsafe { &*self.elf32_get_section_table().offset(offset) }
    }

    #[inline]
    fn elf32_get_num_program_headers(&self) -> u16 {
        self.elf32_get_header().e_phnum
    }

    #[inline]
    fn elf32_get_num_sections(&self) -> u16 {
        self.elf32_get_header().e_shnum
    }

    #[inline]
    fn elf32_get_section_string_table_index(&self) -> u16 {
        self.elf32_get_header().e_shstrndx
    }

    #[inline]
    fn elf32_get_section_name_offset(&self, s: isize) -> u32 {
        self.elf32_get_section_table_offset(s).sh_name
    }

    #[inline]
    fn elf32_get_section_type(&self, s: isize) -> u32 {
        self.elf32_get_section_table_offset(s).sh_type
    }

    #[inline]
    fn elf32_get_section_flags(&self, s: isize) -> u32 {
        self.elf32_get_section_table_offset(s).sh_flags
    }

    #[inline]
    fn elf32_get_section_addr(&self, i: isize) -> u32 {
        self.elf32_get_section_table_offset(i).sh_addr
    }

    #[inline]
    fn elf32_get_section_offset(&self, i: isize) -> u32 {
        self.elf32_get_section_table_offset(i).sh_offset
    }

    #[inline]
    fn elf32_get_section_size(&self, i: isize) -> u32 {
        self.elf32_get_section_table_offset(i).sh_size
    }

    #[inline]
    fn elf32_get_section_link(&self, i: isize) -> u32 {
        self.elf32_get_section_table_offset(i).sh_link
    }

    #[inline]
    fn elf32_get_section_info(&self, i: isize) -> u32 {
        self.elf32_get_section_table_offset(i).sh_info
    }

    #[inline]
    fn elf32_get_section_addr_align(&self, i: isize) -> u32 {
        self.elf32_get_section_table_offset(i).sh_addralign
    }

    #[inline]
    fn elf32_get_section_entry_size(&self, i: isize) -> u32 {
        self.elf32_get_section_table_offset(i).sh_entsize
    }

    #[inline]
    fn elf32_get_program_header_type(&self, ph: isize) -> u32 {
        self.elf32_get_program_header_table_offset(ph).p_type
    }

    #[inline]
    fn elf32_get_program_header_flags(&self, ph: isize) -> u32 {
        self.elf32_get_program_header_table_offset(ph).p_flags
    }
    #[inline]
    fn elf32_get_program_header_offset(&self, ph: isize) -> u32 {
        self.elf32_get_program_header_table_offset(ph).p_offset
    }

    #[inline]
    fn elf32_get_program_header_vaddr(&self, ph: isize) -> u32 {
        self.elf32_get_program_header_table_offset(ph).p_vaddr
    }

    #[inline]
    fn elf32_get_program_header_paddr(&self, ph: isize) -> u32 {
        self.elf32_get_program_header_table_offset(ph).p_paddr
    }

    #[inline]
    fn elf32_get_program_header_file_size(&self, ph: isize) -> u32 {
        self.elf32_get_program_header_table_offset(ph).p_filesz
    }

    #[inline]
    fn elf32_get_program_header_memory_size(&self, ph: isize) -> u32 {
        self.elf32_get_program_header_table_offset(ph).p_memsz
    }

    #[inline]
    fn elf32_get_program_header_align(&self, ph: isize) -> u32 {
        self.elf32_get_program_header_table_offset(ph).p_align
    }
}

// elf64
impl Elf {
    fn elf64_check_file(&mut self) -> isize {
        if  size_of::<usize>() != size_of::<u64>() ||
            self.elf_size < size_of::<libc::Elf64_Ehdr>() ||
            self.check_magic() < 0 {
            return -1;
        }

        let header = self.elf64_get_header();
        if  header.e_ident[EI_CLASS] != ELFCLASS64 ||
            header.e_ident[EI_CLASS] as usize != size_of::<libc::Elf64_Phdr>() ||
            header.e_shentsize as usize != size_of::<libc::Elf64_Shdr>() ||
            header.e_shstrndx >= header.e_shnum {
            return -1;
        }

        self.elf_class = header.e_ident[EI_CLASS];
        0
    }

    fn elf64_check_program_header_table(&self) -> isize {
        let header = self.elf64_get_header();
        let ph_end = header.e_phoff + (header.e_phentsize * header.e_phnum) as u64;
        if self.elf_size < ph_end as usize || ph_end < header.e_phoff {
            -1
        } else {
            0
        }
    }

    fn elf64_check_section_table(&self) -> isize {
        let header = self.elf64_get_header();
        let sh_end = header.e_shoff + (header.e_shentsize * header.e_shnum) as u64;
        if self.elf_size < sh_end as usize || sh_end < header.e_shoff {
            -1
        } else {
            0
        }
    }

    #[inline]
    fn is_elf64(&self) -> bool {
        self.elf_class == ELFCLASS64
    }

    #[inline]
    fn elf64_get_header(&self) -> &libc::Elf64_Ehdr {
        unsafe { &*(self.elf_file as *const libc::Elf64_Ehdr) }
    }

    #[inline]
    fn elf64_get_entry_point(&self) -> u64 {
        self.elf64_get_header().e_entry
    }

    #[inline]
    fn elf64_get_program_header_table(&self) -> *const libc::Elf64_Phdr {
        unsafe { self.elf_file.offset(self.elf64_get_header().e_phoff as isize) as *const libc::Elf64_Phdr }
    }

    #[inline]
    fn elf64_get_program_header_table_offset(&self, offset: isize) -> &libc::Elf64_Phdr {
        unsafe { &*self.elf64_get_program_header_table().offset(offset) }
    }

    #[inline]
    fn elf64_get_section_table(&self) -> *const libc::Elf64_Shdr {
        unsafe { self.elf_file.offset(self.elf64_get_header().e_shoff as isize) as *const libc::Elf64_Shdr }
    }

    #[inline]
    fn elf64_get_section_table_offset(&self, offset: isize) -> &libc::Elf64_Shdr {
        unsafe { &*self.elf64_get_section_table().offset(offset) }
    }

    #[inline]
    fn elf64_get_num_program_headers(&self) -> u16 {
        self.elf64_get_header().e_phnum
    }

    #[inline]
    fn elf64_get_num_sections(&self) -> u16 {
        self.elf64_get_header().e_shnum
    }

    #[inline]
    fn elf64_get_section_string_table_index(&self) -> u16 {
        self.elf64_get_header().e_shstrndx
    }

    #[inline]
    fn elf64_get_section_name_offset(&self, s: isize) -> u32 {
        self.elf64_get_section_table_offset(s).sh_name
    }

    #[inline]
    fn elf64_get_section_type(&self, s: isize) -> u32 {
        self.elf64_get_section_table_offset(s).sh_type
    }

    #[inline]
    fn elf64_get_section_flags(&self, s: isize) -> u64 {
        self.elf64_get_section_table_offset(s).sh_flags
    }

    #[inline]
    fn elf64_get_section_addr(&self, i: isize) -> u64 {
        self.elf64_get_section_table_offset(i).sh_addr
    }

    #[inline]
    fn elf64_get_section_offset(&self, i: isize) -> u64 {
        self.elf64_get_section_table_offset(i).sh_offset
    }

    #[inline]
    fn elf64_get_section_size(&self, i: isize) -> u64 {
        self.elf64_get_section_table_offset(i).sh_size
    }

    #[inline]
    fn elf64_get_section_link(&self, i: isize) -> u32 {
        self.elf64_get_section_table_offset(i).sh_link
    }

    #[inline]
    fn elf64_get_section_info(&self, i: isize) -> u32 {
        self.elf64_get_section_table_offset(i).sh_info
    }

    #[inline]
    fn elf64_get_section_addr_align(&self, i: isize) -> u64 {
        self.elf64_get_section_table_offset(i).sh_addralign
    }

    #[inline]
    fn elf64_get_section_entry_size(&self, i: isize) -> u64 {
        self.elf64_get_section_table_offset(i).sh_entsize
    }

    #[inline]
    fn elf64_get_program_header_type(&self, ph: isize) -> u32 {
        self.elf64_get_program_header_table_offset(ph).p_type
    }

    #[inline]
    fn elf64_get_program_header_flags(&self, ph: isize) -> u32 {
        self.elf64_get_program_header_table_offset(ph).p_flags
    }
    #[inline]
    fn elf64_get_program_header_offset(&self, ph: isize) -> u64 {
        self.elf64_get_program_header_table_offset(ph).p_offset
    }

    #[inline]
    fn elf64_get_program_header_vaddr(&self, ph: isize) -> u64 {
        self.elf64_get_program_header_table_offset(ph).p_vaddr
    }

    #[inline]
    fn elf64_get_program_header_paddr(&self, ph: isize) -> u64 {
        self.elf64_get_program_header_table_offset(ph).p_paddr
    }

    #[inline]
    fn elf64_get_program_header_file_size(&self, ph: isize) -> u64 {
        self.elf64_get_program_header_table_offset(ph).p_filesz
    }

    #[inline]
    fn elf64_get_program_header_memory_size(&self, ph: isize) -> u64 {
        self.elf64_get_program_header_table_offset(ph).p_memsz
    }

    #[inline]
    fn elf64_get_program_header_align(&self, ph: isize) -> u64 {
        self.elf64_get_program_header_table_offset(ph).p_align
    }
}

impl Elf {
    pub fn new() -> Self {
        Self {
            elf_file: 0 as *const u8,
            elf_size: 0,
            elf_class: 0,
        }
    }

    pub fn new_file(&mut self, file: *const u8, size: usize) -> isize {
        self.new_file_maybe_unsafe(file, size, true, true)
    }

    fn new_file_maybe_unsafe(&mut self, file: *const u8, size: usize, check_pht: bool, check_st: bool) -> isize {
        self.elf_file = file;
        self.elf_size = size;

        let mut status = self.check_file();
        if status < 0 {
            return status;
        }

        if check_pht {
            status = self.check_program_header_table();
            if status < 0 {
                return status;
            }
        }

        if check_st {
            status = self.check_section_table();
            if status < 0 {
                return status;
            }
        }

        status
    }

    fn check_magic(&self) -> isize {
        if unsafe { libc::memcmp(self.elf_file as *const libc::c_void, ELFMAG.as_ptr() as *const libc::c_void, SELFMAG) } != 0 {
            -1
        } else {
            0
        }
    }

    fn check_file(&mut self) -> isize {
        if self.elf32_check_file() == 0 || self.elf64_check_file() == 0 {
            0
        } else {
            -1
        }
    }

    fn check_program_header_table(&self) -> isize {
        if self.is_elf32() {
            self.elf32_check_program_header_table()
        } else {
            self.elf64_check_program_header_table()
        }
    }

    fn check_section_table(&self) -> isize {
        if self.is_elf32() {
            self.elf32_check_section_table()
        } else {
            self.elf64_check_section_table()
        }
    }

    pub fn get_entry_point(&self) -> usize {
        if self.is_elf32() {
            self.elf32_get_entry_point() as usize
        } else {
            self.elf64_get_entry_point() as usize
        }
    }

    pub fn get_num_program_headers(&self) -> usize {
        if self.is_elf32() {
            self.elf32_get_num_program_headers() as usize
        } else {
            self.elf64_get_num_program_headers() as usize
        }
    }

    fn get_num_sections(&self) -> usize {
        if self.is_elf32() {
            self.elf32_get_num_sections() as usize
        } else {
            self.elf64_get_num_sections() as usize
        }
    }

    fn get_section_string_table_index(&self) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_string_table_index() as usize
        } else {
            self.elf64_get_section_string_table_index() as usize
        }
    }

    fn get_section_name_offset(&self, i: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_name_offset(i as isize) as usize
        } else {
            self.elf64_get_section_name_offset(i as isize) as usize
        }
    }

    fn get_section_type(&self, i: usize) -> u32 {
        if self.is_elf32() {
            self.elf32_get_section_type(i as isize)
        } else {
            self.elf64_get_section_type(i as isize)
        }
    }

    fn get_section_flags(&self, i: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_flags(i as isize) as usize
        } else {
            self.elf64_get_section_flags(i as isize) as usize
        }
    }

    fn get_section_addr(&self, i: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_addr(i as isize) as usize
        } else {
            self.elf64_get_section_addr(i as isize) as usize
        }
    }

    fn get_section_offset(&self, i: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_offset(i as isize) as usize
        } else {
            self.elf64_get_section_offset(i as isize) as usize
        }
    }

    fn get_section_size(&self, i: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_size(i as isize)  as usize
        } else {
            self.elf64_get_section_size(i as isize)  as usize
        }
    }

    fn get_section_link(&self, i: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_link(i as isize)  as usize
        } else {
            self.elf64_get_section_link(i as isize)  as usize
        }
    }

    fn get_section_info(&self, i: usize) -> u32 {
        if self.is_elf32() {
            self.elf32_get_section_info(i as isize)
        } else {
            self.elf64_get_section_info(i as isize)
        }
    }

    fn get_section_addr_align(&self, i: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_addr_align(i as isize) as usize
        } else {
            self.elf64_get_section_addr_align(i as isize) as usize
        }
    }

    fn get_section_entry_size(&self, i: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_section_entry_size(i as isize)  as usize
        } else {
            self.elf64_get_section_entry_size(i as isize)  as usize
        }
    }

    fn get_section(&self, i: usize) -> *const u8 {
        if i == 0 || i >= self.get_num_sections() {
            return 0 as *const u8;
        }

        let section_offset = self.get_section_offset(i);
        let section_size   = self.get_section_size(i);
        if section_size == 0 {
            return 0 as *const u8;
        }

        let section_end = section_offset + section_size;
        if section_end > self.elf_size || section_end < section_offset {
            return 0 as *const u8;
        }

        unsafe { self.elf_file.offset(section_offset as isize) }
    }

    fn get_string_table(&self, string_segment: usize) -> *const u8 {
        let string_table = self.get_section(string_segment);
        if string_table as usize == 0 {
            return 0 as *const u8;
        }

        if self.get_section_type(string_segment) as usize != SHT_STRTAB {
            return 0 as *const u8;
        }

        let size = self.get_section_size(string_segment);
        if unsafe { *string_table.offset((size - 1) as isize) } != 0 {
            return 0 as *const u8;
        }

        return string_table;
    }

    fn get_section_string_table(&self) -> *const u8 {
        let index = self.get_section_string_table_index();
        self.get_string_table(index)
    }

    fn get_section_name(&self, i: usize) -> *const u8 {
        let str_table_idx = self.get_section_string_table_index();
        let string_table = self.get_string_table(str_table_idx);
        let offset = self.get_section_name_offset(i);
        let size = self.get_section_size(str_table_idx);

        if string_table as usize == 0 || offset > size {
            panic!("<corrupted>");
        } else {
            unsafe { string_table.offset(offset as isize) }
        }
    }

    fn get_section_named(&self, str: *const u8, id: Option<&mut usize>) -> *const u8 {
        let num_sections = self.get_num_sections();
        for i in 0..num_sections {
            // libc::c_char on different platform is defined differently
            // on riscv64gc-unknown-linux-gnu type c_char = u8
            if unsafe { libc::strcmp(str as *const u8, self.get_section_name(i) as *const u8) }== 0 {
                if let Some(ret) = id {
                    *ret = i;
                }
                return self.get_section(i);
            }
        }
        0 as *const u8
    }

    pub fn get_program_header_type(&self, ph: usize) -> u32 {
        if self.is_elf32() {
            self.elf32_get_program_header_type(ph as isize)
        } else {
            self.elf64_get_program_header_type(ph as isize)
        }
    }

    fn get_program_header_offset(&self, ph: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_program_header_offset(ph as isize) as usize
        } else {
            self.elf64_get_program_header_offset(ph as isize) as usize
        }
    }

    pub fn get_program_header_vaddr(&self, ph: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_program_header_vaddr(ph as isize) as usize
        } else {
            self.elf64_get_program_header_vaddr(ph as isize) as usize
        }
    }

    fn get_program_header_paddr(&self, ph: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_program_header_paddr(ph as isize) as usize
        } else {
            self.elf64_get_program_header_paddr(ph as isize) as usize
        }
    }

    pub fn get_program_header_file_size(&self, ph: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_program_header_file_size(ph as isize) as usize
        } else {
            self.elf64_get_program_header_file_size(ph as isize) as usize
        }
    }

    pub fn get_program_header_memory_size(&self, ph: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_program_header_memory_size(ph as isize) as usize
        } else {
            self.elf64_get_program_header_memory_size(ph as isize) as usize
        }
    }

    fn get_program_header_flags(&self, ph: usize) -> u32 {
        if self.is_elf32() {
            self.elf32_get_program_header_flags(ph as isize)
        } else {
            self.elf64_get_program_header_flags(ph as isize)
        }
    }

    fn get_program_header_align(&self, ph: usize) -> usize {
        if self.is_elf32() {
            self.elf32_get_program_header_align(ph as isize) as usize
        } else {
            self.elf64_get_program_header_align(ph as isize) as usize
        }
    }

    pub fn get_program_segment(&self, ph: usize) -> *const u8 {
        let offset = self.get_program_header_offset(ph);
        let file_size = self.get_program_header_file_size(ph);
        let segment_end = offset + file_size;

        if self.elf_size < segment_end || segment_end < offset {
            0 as *const u8
        } else {
            unsafe { self.elf_file.offset(offset as isize) }
        }
    }

    pub fn get_memory_bounds(&self, addr_type: ElfAddrType, min: &mut usize, max: &mut usize) -> isize {
        let mut mem_min = usize::MAX;
        let mut mem_max = 0;

        for i in 0..self.get_num_program_headers() {
            if self.get_program_header_memory_size(i) == 0 {
                continue;
            }


            let sect_min = if addr_type == ElfAddrType::PHYSICAL {
                self.get_program_header_paddr(i)
            } else {
                self.get_program_header_vaddr(i)
            };
            let sect_max = sect_min + self.get_program_header_memory_size(i);

            if sect_max > mem_max {
                mem_max = sect_max;
            }
            if sect_min < mem_min {
                mem_min = sect_min;
            }
        }
        *min = mem_min;
        *max = mem_max;

        1
    }

    fn vaddr_in_program_header(&self, ph: usize, vaddr: usize) -> isize {
        let min = self.get_program_header_vaddr(ph);
        let max = min + self.get_program_header_memory_size(ph);
        if vaddr >= min && vaddr < max {
            1
        } else {
            0
        }
    }

    fn vtop_program_header(&self, ph: usize, vaddr: usize) -> usize {
        let ph_phys = self.get_program_header_paddr(ph);
        let ph_virt = self.get_program_header_vaddr(ph);
        let paddr = vaddr - ph_virt + ph_phys;
        paddr
    }

    fn load_file(&mut self, addr_type: ElfAddrType) -> isize {
        for i in 0..self.get_num_program_headers() {
            let mut dest = if addr_type == ElfAddrType::PHYSICAL {
                self.get_program_header_paddr(i)
            } else {
                self.get_program_header_vaddr(i)
            } as *mut libc::c_void;
            let len = self.get_program_header_file_size(i);
            let src = unsafe { self.elf_file.offset(self.get_program_header_offset(i) as isize) };
            unsafe {
                libc::memcpy(dest, src as *const libc::c_void, len);
                dest = dest.offset(len as isize);
                libc::memset(dest, 0, self.get_program_header_memory_size(i) - len);
            };
        }
        1
    }
}
