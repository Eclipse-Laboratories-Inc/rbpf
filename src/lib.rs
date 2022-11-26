// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for syscalls)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Virtual machine and JIT compiler for eBPF programs.
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.png",
    html_favicon_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.ico"
)]

extern crate byteorder;
extern crate combine;
extern crate hash32;
extern crate log;
extern crate rand;
extern crate thiserror;

pub mod aligned_memory;
mod asm_parser;
pub mod assembler;
pub mod call_frames;
#[cfg(feature = "debugger")]
pub mod debugger;
pub mod disassembler;
pub mod ebpf;
pub mod elf;
pub mod elf_parser;
pub mod elf_parser_glue;
pub mod error;
pub mod fuzz;
pub mod insn_builder;
pub mod interpreter;
#[cfg(feature = "jit")]
mod jit;
pub mod memory_region;
pub mod static_analysis;
pub mod syscalls;
pub mod user_error;
pub mod verifier;
pub mod vm;
#[cfg(feature = "jit")]
mod x86;
pub mod compiler;
pub mod riscv;

trait ErrCheckedArithmetic: Sized {
    fn err_checked_add(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    fn err_checked_sub(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    fn err_checked_mul(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    fn err_checked_div(self, other: Self) -> Result<Self, ArithmeticOverflow>;
}
struct ArithmeticOverflow;

macro_rules! impl_err_checked_arithmetic {
    ($($ty:ty),*) => {
        $(
            impl ErrCheckedArithmetic for $ty {
                fn err_checked_add(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_add(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_sub(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_sub(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_mul(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_mul(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_div(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_div(other).ok_or(ArithmeticOverflow)
                }
            }
        )*
    }
}

impl_err_checked_arithmetic!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
