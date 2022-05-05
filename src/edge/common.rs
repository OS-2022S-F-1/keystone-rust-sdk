pub type EdgeDataOffset = usize;
pub type UnsafePointer = usize;
pub type EdgeCallWrapper = fn(_: *mut u8) -> ();

pub const MAX_EDGECALL: usize = 10;

pub enum CallStatus {
    Ok,
    BadCallID,
    BadOffset,
    BadPtr,
    Error,
    SyscallFailed,
}

pub struct EdgeData {
    pub offset: EdgeDataOffset,
    pub size: usize,
}

pub struct EdgeAppRetData {
    app_ptr: UnsafePointer,
    len: usize,
}

pub struct EdgeReturn {
    pub call_status: CallStatus,
    pub call_ret_offset: EdgeDataOffset,
    pub call_ret_size: usize,
}

pub struct EdgeCall {
    pub call_id: usize,
    pub call_arg_offset: EdgeDataOffset,
    pub call_arg_size: usize,
    pub return_data: EdgeReturn,
}
