# keystone-rust-sdk

This repo is sdk for [Rust-Keystone](https://github.com/OS-2022S-F-1/rust_keystone), contains the necessary tools to create an enclave.

To create an app running in enclave, you need to code normal app and enclave app separately.
Normal app runs in host os (for Rust-Keystone, we use zCore), in which you create an enclave handle and run it like this:
```rust
use keystone_rust_sdk::{Params, ElfData, Enclave};
fn main(args: Vec<String>) -> i32 {
    let mut params = Params::new();
    let mut ret: usize = 0;
    let elf_data = ElfData::new(args.get(1).unwrap().as_str(), args.get(2).unwrap().as_str());
    let mut enclave = Enclave::new(&elf_data, params, 0).unwrap();
    enclave.run(&mut ret);
    0
}
```
Enclave app can use resource from normal app by using 'outbound call', these syscalls will be handled by functions registered in normal app.
Here's how you register outbound call handler in normal app:
```rust
use keystone_rust_sdk::{EdgeCallHandler, Params, ElfData, Enclave};
fn main(args: Vec<String>) -> i32 {
    let mut params = Params::new();
    let mut ret: usize = 0;
    let elf_data = ElfData::new(args.get(1).unwrap().as_str(), args.get(2).unwrap().as_str());
    let mut enclave = Enclave::new(&elf_data, params, 0).unwrap();
    
    let mut handler = EdgeCallHandler::init_internals(enclave.get_shared_buffer() as usize, enclave.get_shared_buffer_size());
    handler.register_call(8, move |_: *mut u8| {
        println!("ocall from enclave!");
    });
    enclave.register_ocall_handler(handler);
    
    enclave.run(&mut ret);
    0
}
```
Use `eapp_ret` to end enclave app and use `ocall` to launch an outbound call:
```rust
use keystone_rust_sdk::{ocall, eapp_ret};
fn main(_args: Vec<String>) -> ! {
    let data = [0u8; 32];
    let mut ret  = [0u8; 32];
    ocall(8, data.as_ptr(), 32, ret.as_mut_ptr(), 32);
    eapp_ret(0);
}
```