#![no_main]

use libfuzzer_sys::fuzz_target;

mod riscv_common;
use crate::riscv_common::run_bpf;

fuzz_target!(|data: [u64; 2]| {
    let (x, y) = (data[0], data[1]);
    let result = run_bpf(format!("
        lddw r0, {x:#x}
        lddw r1, {y:#x}
        add r0, r1
    "));
    assert_eq!(result[0], x.wrapping_add(y), "Output disagreed with expected value");
});
