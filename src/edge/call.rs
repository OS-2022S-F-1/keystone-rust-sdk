use core::{mem, ptr};
use super::common::{EdgeDataOffset, UnsafePointer, EdgeCallWrapper, MAX_EDGECALL, EdgeData, EdgeCall};

pub static mut SHARED_START: UnsafePointer = 0;
pub static mut SHARED_LEN: usize = 0;

pub struct EdgeCallHandler {
    shared_start: UnsafePointer,
    shared_len: usize,
    pub edge_call_table: [Option<EdgeCallWrapper>; MAX_EDGECALL],
}

impl EdgeCallHandler {
    #[inline]
    pub fn init_internals(shared_start: UnsafePointer, shared_len: usize) -> Self {
        Self {
            shared_start,
            shared_len,
            edge_call_table: [None; MAX_EDGECALL]
        }
    }

    #[inline]
    pub fn get_ptr_from_offset(&self, offset: EdgeDataOffset, data_len: usize, ptr: &mut UnsafePointer) -> isize {
        if offset + data_len > UnsafePointer::max_value() - self.shared_start || offset + data_len > self.shared_len {
            -1
        } else {
            *ptr = self.shared_start + offset;
            0
        }
    }

    #[inline]
    pub fn check_ptr_valid(&self, ptr: UnsafePointer, data_len: usize) -> isize {
        if ptr > self.shared_start + self.shared_len || ptr < self.shared_start {
            1
        } else if data_len > UnsafePointer::max_value() - ptr {
            2
        } else if ptr + data_len > self.shared_start + self.shared_len {
            3
        } else {
            0
        }
    }

    #[inline]
    pub fn get_offset_from_ptr(&self, ptr: UnsafePointer, data_len: usize, offset: &mut EdgeDataOffset) -> isize {
        let valid = self.check_ptr_valid(ptr, data_len);
        if valid != 0 {
            valid
        } else {
            *offset = ptr - self.shared_start;
            0
        }
    }

    #[inline]
    pub fn args_ptr(&self, edge_call: &EdgeCall, ptr: &mut UnsafePointer, size: &mut usize) -> isize {
        *size = edge_call.return_data.call_ret_size;
        self.get_ptr_from_offset(edge_call.call_arg_offset, *size, ptr)
    }

    #[inline]
    pub fn ret_ptr(&self, edge_call: &EdgeCall, ptr: &mut UnsafePointer, size: &mut usize) -> isize {
        *size = edge_call.return_data.call_ret_size;
        self.get_ptr_from_offset(edge_call.return_data.call_ret_offset, *size, ptr)
    }

    #[inline]
    pub fn setup_call(&self, edge_call: &mut EdgeCall, ptr: &mut UnsafePointer, size: usize) -> isize {
        edge_call.call_arg_size = size;
        self.get_offset_from_ptr(*ptr, size, &mut edge_call.call_arg_offset)
    }

    #[inline]
    pub fn setup_ret(&self, edge_call: &mut EdgeCall, ptr: &mut UnsafePointer, size: usize) -> isize {
        edge_call.return_data.call_ret_size = size;
        self.get_offset_from_ptr(*ptr, size, &mut edge_call.return_data.call_ret_offset)
    }

    #[inline]
    pub fn setup_wrapped_ret(&self, edge_call: &mut EdgeCall, ptr: &mut UnsafePointer, size: usize) -> isize {
        let mut data_wrapper = EdgeData {
            size,
            offset: 0
        };
        self.get_offset_from_ptr(
            self.shared_start + mem::size_of::<EdgeCall>() + mem::size_of::<EdgeData>(),
            mem::size_of::<EdgeData>(), &mut data_wrapper.offset
        );

        unsafe {
            ptr::copy_nonoverlapping(*ptr as *const u8, (self.shared_start + mem::size_of::<EdgeCall>() + mem::size_of::<EdgeData>()) as *mut u8, size);
            ptr::copy_nonoverlapping(&data_wrapper as *const EdgeData, (self.shared_start + mem::size_of::<EdgeCall>()) as *mut EdgeData, 1);
        };

        edge_call.return_data.call_ret_size = mem::size_of::<EdgeData>();
        self.get_offset_from_ptr(self.shared_start + mem::size_of::<EdgeCall>(), mem::size_of::<EdgeData>(), &mut edge_call.return_data.call_ret_offset)
    }

    #[inline]
    pub fn data_ptr(&self) -> UnsafePointer {
        self.shared_start + mem::size_of::<EdgeCall>()
    }
}
