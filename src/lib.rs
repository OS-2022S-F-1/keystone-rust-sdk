#![no_std]
#![allow(unused)]
extern crate alloc;

mod edge;
mod common;
mod app;
mod host;
#[macro_use]
pub mod console;

pub use app::syscall::{ocall, eapp_ret};
pub use edge::EdgeCallHandler;
pub use host::{Error, Params, Enclave, ElfData};
pub use console::{flush, STDIN, STDOUT};
