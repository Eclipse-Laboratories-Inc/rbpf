#![no_main]

use libfuzzer_sys::fuzz_target;

mod riscv_common;
use crate::riscv_common::run_bpf;

fuzz_target!(|data: u64| {
    let result = run_bpf(format!("
        lddw r0, {data:#x}
    "));
    assert_eq!(result[0], data, "Output disagreed with expected value");
});
