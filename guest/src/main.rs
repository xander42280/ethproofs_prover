#![no_std]
#![no_main]

extern crate libc;

extern crate alloc;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

zkm_runtime::entrypoint!(main);

pub fn main() {
    ethereum_test();
}

fn ethereum_test() {
    let input: Vec<u8> = zkm_runtime::io::read();
    let suite: models::TestSuite = serde_json::from_slice(s).map_err(|e| e).unwrap();
    assert!(check::execute_test_suite(suite).is_ok());
}
