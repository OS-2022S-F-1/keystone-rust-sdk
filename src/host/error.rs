use core::fmt::{Debug, Formatter, Result};

#[derive(PartialEq)]
pub enum Error {
    Success = 0,
    FileInitFailure,
    DeviceInitFailure,
    DeviceError,
    IoctlErrorCreate,
    IoctlErrorDestroy,
    IoctlErrorFinalize,
    IoctlErrorRun,
    IoctlErrorResume,
    IoctlErrorUTMInit,
    DeviceMemoryMapError,
    ELFLoadFailure,
    InvalidEnclave,
    VSpaceAllocationFailure,
    PageAllocationFailure,
    EdgeCallHost,
    EnclaveInterrupted,
}


#[allow(non_snake_case)]
impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let mut f = f.debug_struct("Keystone sdk");
        f.field("flag", &self);
        f.finish()
    }
}
