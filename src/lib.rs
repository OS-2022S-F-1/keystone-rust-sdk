#![no_std]
extern crate alloc;

mod edge;
mod common;
mod app;
mod host;

pub use edge::EdgeCallHandler;
pub use host::{Error, Params, Enclave};
