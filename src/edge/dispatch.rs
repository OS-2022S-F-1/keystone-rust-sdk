use super::common::{EdgeCallWrapper, MAX_EDGECALL, CallStatus, EdgeCall};
use super::call::{EdgeCallHandler};
use super::syscall::{EDGECALL_SYSCALL};

impl EdgeCallHandler {
    pub fn incoming_call_dispatch(&self, buffer: *mut u8) {
        let mut edge_call = unsafe { &mut *(buffer as *mut EdgeCall) };

        if edge_call.call_id == EDGECALL_SYSCALL {
            self.incoming_syscall(edge_call);
            return;
        }

        if edge_call.call_id > MAX_EDGECALL || self.edge_call_table[edge_call.call_id].is_none() {
            edge_call.return_data.call_status = CallStatus::BadCallID;
            return;
        }

        self.edge_call_table[edge_call.call_id].unwrap()(buffer);
    }

    pub fn register_call(&mut self, call_id: usize, func: EdgeCallWrapper) -> isize {
        if call_id > MAX_EDGECALL {
            -1
        } else {
            self.edge_call_table[call_id] = Some(func);
            0
        }
    }
}
