use core::fmt::{Debug, Result};

#[derive(PartialEq, Debug)]
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
