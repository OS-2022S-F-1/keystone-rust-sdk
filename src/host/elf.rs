use xmas_elf::{ElfFile, program::ProgramHeader};
use super::common::PAGE_SIZE;

pub trait KeystoneElfFile {
    fn get_memory_bounds(&self) -> (usize, usize);
    fn get_total_memory_pages(&self) -> usize;
    fn get_program_segment(&self, header: &ProgramHeader) -> *const u8;
}

impl<'a> KeystoneElfFile for ElfFile<'a> {
    fn get_memory_bounds(&self) -> (usize, usize) {
        let mut mem_min = usize::MAX;
        let mut mem_max = 0;

        for header in self.program_iter() {
            if header.mem_size() == 0 {
                continue;
            }

            let sect_min = header.virtual_addr() as usize;
            let sect_max = sect_min + header.mem_size() as usize;

            if sect_max > mem_max {
                mem_max = sect_max;
            }
            if sect_min < mem_min {
                mem_min = sect_min;
            }
        }

        (mem_min, mem_max)
    }


    fn get_total_memory_pages(&self) -> usize {
        let mut pages: usize = 0;

        for header in self.program_iter() {
            pages += (header.mem_size() as usize + PAGE_SIZE - 1) / PAGE_SIZE;
        }

        pages
    }

    fn get_program_segment(&self, header: &ProgramHeader) -> *const u8 {
        let offset = header.offset() as usize;
        let file_size = header.file_size() as usize;
        let segment_end = offset + file_size;

        if self.input.len() < segment_end || segment_end < offset {
            0 as *mut u8
        } else {
            unsafe { self.input.as_ptr().offset(offset as isize) }
        }
    }
}
