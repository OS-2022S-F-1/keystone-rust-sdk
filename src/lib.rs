#![no_std]
extern crate alloc;

mod edge;
mod common;
mod app;
mod host;
#[macro_use]
pub mod console;

pub use edge::EdgeCallHandler;
pub use host::{Error, Params, Enclave, ElfData};
pub use console::{flush, STDIN, STDOUT};