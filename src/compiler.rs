#![allow(clippy::integer_arithmetic)]
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff addition)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
// Copyright 2022 Eclipse Labs
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>.
// This file may not be copied, modified, or distributed except according to those terms.

//! eBPF to RISC-V compiler

#![allow(clippy::deprecated_cfg_attr)]
#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unreachable_code)]

extern crate libc;

use std::{
    fmt::{Debug, Error as FormatterError, Formatter}, mem,
    ops::{Index, IndexMut},
    ptr,
};
use rand::{rngs::SmallRng, Rng, SeedableRng};

use crate::{
    elf::Executable,
    vm::{Config, InstructionMeter},
    ebpf::{self, FIRST_SCRATCH_REG, SCRATCH_REGS, FRAME_PTR_REG, MM_STACK_START, STACK_PTR_REG, INSN_SIZE},
    error::{UserDefinedError, EbpfError},
    memory_region::AccessType,
    riscv::*,
};

const MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH: usize = 4096;
const MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION: usize = 110;
const MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT: usize = 13;

pub struct ProgramSections {
    /// A `*const u8` pointer into the text_section for each BPF instruction
    pub pc_section: &'static mut [usize],
    /// The x86 machinecode
    pub text_section: &'static mut [u8],
}

macro_rules! libc_error_guard {
    (succeeded?, mmap, $addr:expr, $($arg:expr),*) => {{
        *$addr = libc::mmap(*$addr, $($arg),*);
        *$addr != libc::MAP_FAILED
    }};
    (succeeded?, $function:ident, $($arg:expr),*) => {
        libc::$function($($arg),*) == 0
    };
    ($function:ident, $($arg:expr),*) => {{
        const RETRY_COUNT: usize = 3;
        for i in 0..RETRY_COUNT {
            if libc_error_guard!(succeeded?, $function, $($arg),*) {
                break;
            } else if i + 1 == RETRY_COUNT {
                let args = vec![$(format!("{:?}", $arg)),*];
                #[cfg(any(target_os = "freebsd", target_os = "ios", target_os = "macos"))]
                let errno = *libc::__error();
                #[cfg(target_os = "linux")]
                let errno = *libc::__errno_location();
                return Err(EbpfError::LibcInvocationFailed(stringify!($function), args, errno));
            }
        }
    }};
}

#[allow(unused_variables)]
impl ProgramSections {
    fn new<E: UserDefinedError>(pc: usize, code_size: usize) -> Result<Self, EbpfError<E>> {
        unsafe {
            let pc_loc_table_size = pc * 8;
            let over_allocated_code_size = code_size;
            let mut raw: *mut libc::c_void = std::ptr::null_mut();
            libc_error_guard!(mmap, &mut raw, pc_loc_table_size + over_allocated_code_size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANONYMOUS | libc::MAP_PRIVATE, 0, 0);
            Ok(Self {
                pc_section: std::slice::from_raw_parts_mut(raw as *mut usize, pc),
                text_section: std::slice::from_raw_parts_mut(raw.add(pc_loc_table_size) as *mut u8, over_allocated_code_size),
            })
        }
    }

    fn seal<E: UserDefinedError>(&mut self, text_section_usage: usize) -> Result<(), EbpfError<E>> {
        Ok(())
    }
}

// Used to define subroutines and then call them
// See JitCompiler::set_anchor() and JitCompiler::relative_to_anchor()
const ANCHOR_EPILOGUE: usize = 0;
const ANCHOR_TRACE: usize = 1;
const ANCHOR_RUST_EXCEPTION: usize = 2;
const ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS: usize = 3;
const ANCHOR_EXCEPTION_AT: usize = 4;
const ANCHOR_CALL_DEPTH_EXCEEDED: usize = 5;
const ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT: usize = 6;
const ANCHOR_DIV_BY_ZERO: usize = 7;
const ANCHOR_DIV_OVERFLOW: usize = 8;
const ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION: usize = 9;
const ANCHOR_CALL_UNSUPPORTED_INSTRUCTION: usize = 10;
const ANCHOR_EXIT: usize = 11;
const ANCHOR_SYSCALL: usize = 12;
const ANCHOR_BPF_CALL_PROLOGUE: usize = 13;
const ANCHOR_BPF_CALL_REG: usize = 14;
const ANCHOR_TRANSLATE_PC: usize = 15;
const ANCHOR_TRANSLATE_PC_LOOP: usize = 16;
const ANCHOR_MEMORY_ACCESS_VIOLATION: usize = 17;
const ANCHOR_TRANSLATE_MEMORY_ADDRESS: usize = 25;
const ANCHOR_COUNT: usize = 33; // Update me when adding or removing anchors

const REGISTER_MAP: [[Register; 2]; 11] = [
    [CALLER_SAVED_REGISTERS[1], CALLER_SAVED_REGISTERS[2]],
    [ARGUMENT_REGISTERS[1], ARGUMENT_REGISTERS[2]],
    [ARGUMENT_REGISTERS[3], ARGUMENT_REGISTERS[4]],
    [ARGUMENT_REGISTERS[5], ARGUMENT_REGISTERS[6]],
    [CALLER_SAVED_REGISTERS[3], CALLER_SAVED_REGISTERS[12]],
    [CALLER_SAVED_REGISTERS[13], CALLER_SAVED_REGISTERS[14]],
    [CALLEE_SAVED_REGISTERS[1], CALLEE_SAVED_REGISTERS[2]],
    [CALLEE_SAVED_REGISTERS[3], CALLEE_SAVED_REGISTERS[4]],
    [CALLEE_SAVED_REGISTERS[5], CALLEE_SAVED_REGISTERS[6]],
    [CALLEE_SAVED_REGISTERS[7], CALLEE_SAVED_REGISTERS[8]],
    [CALLEE_SAVED_REGISTERS[9], CALLEE_SAVED_REGISTERS[10]],
];

const RZERO: [Register; 2] = [Register::X0, Register::X0];
const RSCRATCH: [Register; 2] = [CALLEE_SAVED_REGISTERS[11], CALLEE_SAVED_REGISTERS[12]];
const RSCRATCH2: [Register; 2] = [Register::TP, Register::A7];

// Special registers:
//      ARGUMENT_REGISTERS[0]  A0      BPF program counter limit (used by instruction meter)
//                   RSCRATCH  S10,S11 Scratch register
// CALLER_SAVED_REGISTERS[15]  T6      Constant pointer to initial Register::SP - 8
// CALLER_SAVED_REGISTERS[ 0]  RA      Return address
// CALLEE_SAVED_REGISTERS[ 0]  SP      Stack pointer
//                  RSCRATCH2  TP,A7   Secondary scratch

#[inline]
pub fn emit<T>(jit: &mut Compiler, data: T) {
    unsafe {
        let ptr = jit.result.text_section.as_ptr().add(jit.offset_in_text_section);
        #[allow(clippy::cast_ptr_alignment)]
        ptr::write_unaligned(ptr as *mut T, data as T);
    }
    jit.offset_in_text_section += mem::size_of::<T>() as usize;
}

#[inline]
pub fn emit_variable_length(jit: &mut Compiler, size: OperandSize, data: u64) {
    match size {
        OperandSize::S0 => {},
        OperandSize::S8 => emit::<u8>(jit, data as u8),
        OperandSize::S16 => emit::<u16>(jit, data as u16),
        OperandSize::S32 => emit::<u32>(jit, data as u32),
        OperandSize::S64 => emit::<u64>(jit, data),
    }
}

// This function helps the optimizer to inline the machinecode emission while avoiding stack allocations
#[inline(always)]
pub fn emit_ins(comp: &mut Compiler, instruction: RiscVInstruction) {
    instruction.emit(comp);
//  if jit.next_noop_insertion == 0 {
//      jit.next_noop_insertion = jit.diversification_rng.gen_range(0..jit.config.noop_instruction_rate * 2);
//      // RiscVInstruction::noop().emit(jit)?;
//      emit::<u8>(jit, 0x90);
//  } else {
//      jit.next_noop_insertion -= 1;
//  }
}

#[derive(Copy, Clone, Debug)]
pub enum OperandSize {
    S0  = 0,
    S8  = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

/// Indices of slots inside the struct at initial Register::SP
#[allow(dead_code)]
#[repr(C)]
enum EnvironmentStackSlot {
    /// The 12 non-SP CALLEE_SAVED_REGISTERS, divided by 2
    LastSavedRegister = 5,
    /// The current call depth.
    ///
    /// Incremented on calls and decremented on exits. It's used to enforce
    /// config.max_call_depth and to know when to terminate execution.
    CallDepth = 6,
    /// BPF frame pointer (REGISTER_MAP[FRAME_PTR_REG]).
    BpfFramePtr = 7,
    /// The BPF stack pointer (r11). Only used when config.dynamic_stack_frames=true.
    ///
    /// The stack pointer isn't exposed as an actual register. Only sub and add
    /// instructions (typically generated by the LLVM backend) are allowed to
    /// access it. Its value is only stored in this slot and therefore the
    /// register is not tracked in REGISTER_MAP.
    BpfStackPtr = 8,
    /// Constant pointer to optional typed return value
    OptRetValPtr = 9,
    /// Last return value of instruction_meter.get_remaining()
    PrevInsnMeter = 10,
    /// Constant pointer to instruction_meter
    InsnMeterPtr = 11,
    /// CPU cycles accumulated by the stop watch
    StopwatchNumerator = 12,
    /// Number of times the stop watch was used
    StopwatchDenominator = 13,
    /// Bumper for size_of
    SlotCount = 14,
}

#[inline]
fn slot_on_environment_stack(comp: &Compiler, slot: EnvironmentStackSlot) -> i32 {
    -8 * (slot as i32 + comp.environment_stack_key)
}

/* Explanation of the Instruction Meter

    The instruction meter serves two purposes: First, measure how many BPF instructions are
    executed (profiling) and second, limit this number by stopping the program with an exception
    once a given threshold is reached (validation). One approach would be to increment and
    validate the instruction meter before each instruction. However, this would heavily impact
    performance. Thus, we only profile and validate the instruction meter at branches.

    For this, we implicitly sum up all the instructions between two branches.
    It is easy to know the end of such a slice of instructions, but how do we know where it
    started? There could be multiple ways to jump onto a path which all lead to the same final
    branch. This is, where the integral technique comes in. The program is basically a sequence
    of instructions with the x-axis being the program counter (short "pc"). The cost function is
    a constant function which returns one for every point on the x axis. Now, the instruction
    meter needs to calculate the definite integral of the cost function between the start and the
    end of the current slice of instructions. For that we need the indefinite integral of the cost
    function. Fortunately, the derivative of the pc is the cost function (it increases by one for
    every instruction), thus the pc is an antiderivative of the the cost function and a valid
    indefinite integral. So, to calculate an definite integral of the cost function, we just need
    to subtract the start pc from the end pc of the slice. This difference can then be subtracted
    from the remaining instruction counter until it goes below zero at which point it reaches
    the instruction meter limit. Ok, but how do we know the start of the slice at the end?

    The trick is: We do not need to know. As subtraction and addition are associative operations,
    we can reorder them, even beyond the current branch. Thus, we can simply account for the
    amount the start will subtract at the next branch by already adding that to the remaining
    instruction counter at the current branch. So, every branch just subtracts its current pc
    (the end of the slice) and adds the target pc (the start of the next slice) to the remaining
    instruction counter. This way, no branch needs to know the pc of the last branch explicitly.
    Another way to think about this trick is as follows: The remaining instruction counter now
    measures what the maximum pc is, that we can reach with the remaining budget after the last
    branch.

    One problem are conditional branches. There are basically two ways to handle them: Either,
    only do the profiling if the branch is taken, which requires two jumps (one for the profiling
    and one to get to the target pc). Or, always profile it as if the jump to the target pc was
    taken, but then behind the conditional branch, undo the profiling (as it was not taken). We
    use the second method and the undo profiling is the same as the normal profiling, just with
    reversed plus and minus signs.

    Another special case to keep in mind are return instructions. They would require us to know
    the return address (target pc), but in the JIT we already converted that to be a host address.
    Of course, one could also save the BPF return address on the stack, but an even simpler
    solution exists: Just count as if you were jumping to an specific target pc before the exit,
    and then after returning use the undo profiling. The trick is, that the undo profiling now
    has the current pc which is the BPF return address. The virtual target pc we count towards
    and undo again can be anything, so we just set it to zero.
*/

// TODO implement these

#[allow(unused_variables)]
#[inline]
fn emit_validate_instruction_count(jit: &mut Compiler, exclusive: bool, pc: Option<usize>) {
//    // Update `MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT` if you change the code generation here
//    if let Some(pc) = pc {
//        jit.last_instruction_meter_validation_pc = pc;
//        emit_ins(jit, RiscVInstruction::cmp_immediate(OperandSize::S64, ARGUMENT_REGISTERS[0], pc as i64 + 1, None));
//    } else {
//        emit_ins(jit, RiscVInstruction::cmp(OperandSize::S64, RSCRATCH, ARGUMENT_REGISTERS[0], None));
//    }
//    emit_ins(jit, RiscVInstruction::conditional_jump_immediate(if exclusive { 0x82 } else { 0x86 }, jit.relative_to_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS, 6)));
}

#[allow(unused_variables)]
#[inline]
fn emit_profile_instruction_count(jit: &mut Compiler, target_pc: Option<usize>) {
//    match target_pc {
//        Some(target_pc) => {
//            emit_ins(jit, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], target_pc as i64 - jit.pc as i64 - 1, None)); // instruction_meter += target_pc - (jit.pc + 1);
//        },
//        None => {
//            emit_ins(jit, RiscVInstruction::alu(OperandSize::S64, 0x81, 5, ARGUMENT_REGISTERS[0], jit.pc as i64 + 1, None)); // instruction_meter -= jit.pc + 1;
//            emit_ins(jit, RiscVInstruction::alu(OperandSize::S64, 0x01, RSCRATCH, ARGUMENT_REGISTERS[0], jit.pc as i64, None)); // instruction_meter += target_pc;
//        },
//    }
}

#[allow(unused_variables)]
#[inline]
fn emit_validate_and_profile_instruction_count(jit: &mut Compiler, exclusive: bool, target_pc: Option<usize>) {
//    if jit.config.enable_instruction_meter {
//        emit_validate_instruction_count(jit, exclusive, Some(jit.pc));
//        emit_profile_instruction_count(jit, target_pc);
//    }
}

#[allow(dead_code)]
#[allow(unused_variables)]
#[inline]
fn emit_undo_profile_instruction_count(jit: &mut Compiler, target_pc: usize) {
//    if jit.config.enable_instruction_meter {
//        emit_ins(jit, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], jit.pc as i64 + 1 - target_pc as i64, None)); // instruction_meter += (jit.pc + 1) - target_pc;
//    }
}

#[allow(unused_variables)]
#[inline]
fn emit_profile_instruction_count_finalize(jit: &mut Compiler, store_pc_in_exception: bool) {
//    if jit.config.enable_instruction_meter || store_pc_in_exception {
//        emit_ins(jit, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, RSCRATCH, 1, None)); // RSCRATCH += 1;
//    }
//    if jit.config.enable_instruction_meter {
//        emit_ins(jit, RiscVInstruction::alu(OperandSize::S64, 0x29, RSCRATCH, ARGUMENT_REGISTERS[0], 0, None)); // instruction_meter -= pc + 1;
//    }
//    if store_pc_in_exception {
//        emit_ins(jit, RiscVInstruction::load(OperandSize::S64, Register::T6, R10, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::OptRetValPtr))));
//        if jit.err_kind_offset == 1 {
//            emit_store_immediate(jit, OperandSize::S64, R10, 1); // result.is_err = true;
//        }
//        emit_ins(jit, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, RSCRATCH, ebpf::ELF_INSN_DUMP_OFFSET as i64 - 1, None));
//        emit_ins(jit, RiscVInstruction::store(OperandSize::S64, RSCRATCH, R10, X86IndirectAccess::Offset((std::mem::size_of::<u64>() * (jit.err_kind_offset + 1)) as i32))); // result.pc = jit.pc + ebpf::ELF_INSN_DUMP_OFFSET;
//    }
}

enum Value {
    Register([Register; 2]),
//  RegisterIndirect([Register; 2], i32, bool),
//  RegisterPlusConstant32([Register; 2], i32, bool),
    RegisterPlusConstant64([Register; 2], i64, bool),
    Constant64(i64, bool),
}

#[inline]
fn emit_bpf_call(comp: &mut Compiler, dst: Value) {
    // Store PC in case the bounds check fails
    emit_load_immediate(comp, OperandSize::S64, RSCRATCH, comp.pc as i64);

    emit_jump_to_anchor(comp, Register::RA, ANCHOR_BPF_CALL_PROLOGUE);

    match dst {
        Value::Register(reg) => {
            // Move vm target_address into RAX
            emit_push(comp, REGISTER_MAP[0]);
            if reg != REGISTER_MAP[0] {
                emit_mov(comp, OperandSize::S64, reg, REGISTER_MAP[0]);
            }

            emit_jump_to_anchor(comp, Register::RA, ANCHOR_BPF_CALL_REG);

            emit_validate_and_profile_instruction_count(comp, false, None);
//          emit_ins(jit, X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11));
            emit_ins(comp, RiscVInstruction::mv(REGISTER_MAP[0][0], RSCRATCH[0])); // Save target_pc
//          emit_ins(jit, X86Instruction::pop(REGISTER_MAP[0]));
            emit_pop(comp, REGISTER_MAP[0]); // Restore register 0
//          emit_ins(jit, X86Instruction::call_reg(R11, None)); // callq *%r11
            emit_call_reg(comp, RSCRATCH[0]);
        },
        Value::Constant64(target_pc, user_provided) => {
            debug_assert!(!user_provided);
            emit_validate_and_profile_instruction_count(comp, false, Some(target_pc as usize));
//          emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
            emit_load_immediate(comp, OperandSize::S64, RSCRATCH, target_pc as i64);
//          let jump_offset = jit.relative_to_target_pc(target_pc as usize, 5);
//          emit_ins(jit, X86Instruction::call_immediate(jump_offset));
            emit_jump_to_pc(comp, Register::RA, target_pc as usize);
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }

    emit_undo_profile_instruction_count(comp, 0);

//  // Restore the previous frame pointer
//  emit_ins(jit, X86Instruction::pop(REGISTER_MAP[FRAME_PTR_REG]));
    emit_pop(comp, REGISTER_MAP[FRAME_PTR_REG]);
//  let frame_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::BpfFramePtr));
//  emit_ins(jit, X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, frame_ptr_access));
    emit_store_offset(comp, OperandSize::S64, Register::T6, REGISTER_MAP[FRAME_PTR_REG], slot_on_environment_stack(comp, EnvironmentStackSlot::BpfFramePtr));
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
//      emit_ins(jit, X86Instruction::pop(*reg));
        emit_pop(comp, *reg);
    }
}

fn emit_c_call(comp: &mut Compiler, symbol: &'static str, args : &[Value]) {
    let saved_registers = CALLER_SAVED_REGISTERS.to_vec();

    // save registers on stack
    for reg in saved_registers.iter() {
        emit_riscv_push(comp, *reg);
    }

    if args.len() > 4 {
        panic!("too many arguments in emit_c_call!");
    }

    // load arguments
    for value in args.iter().rev() {
        match value {
            Value::Register(reg) => {
                emit_push(comp, *reg);
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            },
        }
    }
    for i in 0..args.len() {
        emit_pop(comp, [ARGUMENT_REGISTERS[i], ARGUMENT_REGISTERS[i+1]]);
    }

    // ensure stack alignment
    emit_ins(comp, RiscVInstruction::addi(Register::X0, RSCRATCH[1], 16));
    emit_ins(comp, RiscVInstruction::remu(Register::SP, RSCRATCH[1], RSCRATCH[0]));
    emit_ins(comp, RiscVInstruction::sub(Register::SP, RSCRATCH[0], Register::SP));

    // add relocation
    comp.relocations.push(RiscVRelocation::Call { offset: comp.offset_in_text_section, symbol });

    // call the function
    emit_long_jump(comp, Register::RA, 0);

    // fix the stack
    emit_ins(comp, RiscVInstruction::add(Register::SP, RSCRATCH[0], Register::SP));

    // put the return values in RSCRATCH
    emit_ins(comp, RiscVInstruction::mv(ARGUMENT_REGISTERS[0], RSCRATCH[0]));
    emit_ins(comp, RiscVInstruction::mv(ARGUMENT_REGISTERS[1], RSCRATCH[1]));

    // pop saved registers
    for reg in saved_registers.iter().rev() {
        emit_riscv_pop(comp, *reg);
    }
}

#[inline]
fn emit_load_symbol_address(comp: &mut Compiler, destination: Register, symbol: &'static str) {
    comp.relocations.push(RiscVRelocation::Hi20 { offset: comp.offset_in_text_section, symbol });
    emit_ins(comp, RiscVInstruction::lui(destination, 0));
    comp.relocations.push(RiscVRelocation::Lo12I { offset: comp.offset_in_text_section, symbol });
    emit_ins(comp, RiscVInstruction::addi(destination, destination, 0));
}

#[inline]
fn emit_address_translation(comp: &mut Compiler, vm_addr: Value) {
    match vm_addr {
        Value::RegisterPlusConstant64(reg, constant, _) => {
            emit_load_immediate(comp, OperandSize::S64, RSCRATCH, constant);
            emit_add(comp, OperandSize::S64, reg, RSCRATCH);
        },
        Value::Constant64(constant, _) => {
            emit_load_immediate(comp, OperandSize::S64, RSCRATCH, constant);
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        },
    }
    emit_c_call(comp, "translate_memory_address", &[Value::Register(RSCRATCH)]);
}

// RISC-V sign-extends the 12-bit immediate, so an extra step is necessary to compensate
#[inline]
fn make_split_immediate(imm: i32) -> (i32, i32) {
    if imm & (1 << 11) == 0 {
        (imm, imm)
    } else {
        (imm + (1 << 12), imm)
    }
}

#[inline]
fn emit_jump_to_anchor(comp: &mut Compiler, return_reg: Register, anchor: usize) {
    emit_jump(comp, return_reg, comp.relative_to_anchor(anchor));
}

#[inline]
fn emit_jump_to_pc(comp: &mut Compiler, return_reg: Register, target_pc: usize) {
    if let Some(offset) = comp.relative_to_target_pc(target_pc) {
        emit_jump(comp, return_reg, offset);
    } else {
        emit_long_jump(comp, return_reg, 0);
    }
}

#[inline]
fn emit_long_jump_to_anchor(comp: &mut Compiler, return_reg: Register, anchor: usize) {
    emit_long_jump(comp, return_reg, comp.relative_to_anchor(anchor));
}

#[inline]
fn emit_long_jump_to_pc(comp: &mut Compiler, return_reg: Register, target_pc: usize) {
    let offset = comp.relative_to_target_pc(target_pc).unwrap_or(0);
    emit_long_jump(comp, return_reg, offset);
}

#[inline]
fn emit_jump(comp: &mut Compiler, return_reg: Register, offset: i32) {
    assert!(offset % 4 == 0);
    // check if the offset is the sign extension of its lower 20 bits
    if (offset >> 19 != 0) && (offset >> 19 != -1) {
        // offset is too big for JAL
        emit_long_jump(comp, return_reg, offset);
    } else {
        emit_ins(comp, RiscVInstruction::jal(return_reg, offset));
    }
}

#[inline]
fn emit_long_jump(comp: &mut Compiler, return_reg: Register, offset: i32) {
    let (upper, lower) = make_split_immediate(offset);
    emit_ins(comp, RiscVInstruction::auipc(RSCRATCH2[0], upper));
    emit_ins(comp, RiscVInstruction::jalr(RSCRATCH2[0], return_reg, lower));
}

#[inline]
fn emit_riscv_li(comp: &mut Compiler, dst: Register, imm: i32) {
    emit_riscv_li_controlled(comp, dst, imm, false);
}

#[inline]
fn emit_riscv_li_controlled(comp: &mut Compiler, dst: Register, imm: i32, force_two_instructions : bool) {
    let (upper, lower) = make_split_immediate(imm);
    if force_two_instructions || upper >> 12 == 0 {
        emit_ins(comp, RiscVInstruction::addi(Register::X0, dst, lower));
    } else {
        emit_ins(comp, RiscVInstruction::lui(dst, upper));
        emit_ins(comp, RiscVInstruction::addi(dst, dst, lower));
    }
}

#[inline]
fn emit_riscv_push(comp: &mut Compiler, source: Register) {
    emit_ins(comp, RiscVInstruction::addi(Register::SP, Register::SP, -4));
    emit_ins(comp, RiscVInstruction::sw(Register::SP, source, 0));
}

#[inline]
fn emit_riscv_pop(comp: &mut Compiler, dst: Register) {
    emit_ins(comp, RiscVInstruction::lw(Register::SP, dst, 0));
    emit_ins(comp, RiscVInstruction::addi(Register::SP, Register::SP, 4));
}

#[inline]
fn emit_load_immediate(comp: &mut Compiler, size: OperandSize, dst: [Register; 2], imm: i64) {
    match size {
        OperandSize::S0  => emit_ins(comp, RiscVInstruction::lui(dst[0], 0)),
        OperandSize::S8  => emit_riscv_li(comp, dst[0], imm as u8 as i32),
        OperandSize::S16 => emit_riscv_li(comp, dst[0], imm as u16 as i32),
        OperandSize::S32 => emit_riscv_li(comp, dst[0], imm as i32),
        OperandSize::S64 => emit_riscv_li(comp, dst[0], imm as i32),
    }
    match size {
        OperandSize::S64 => emit_riscv_li(comp, dst[1], (imm >> 32) as i32),
        _ => emit_riscv_li(comp, dst[1], 0),
    }
}

#[inline]
fn emit_load(comp: &mut Compiler, size: OperandSize, addr: Register, dst: [Register; 2]) {
    emit_load_offset(comp, size, addr, dst, 0);
}

#[inline]
fn emit_load_offset(comp: &mut Compiler, size: OperandSize, addr: Register, dst: [Register; 2], imm: i32) {
    match size {
        OperandSize::S0  => emit_ins(comp, RiscVInstruction::lui(dst[0], imm)),
        OperandSize::S8  => emit_ins(comp, RiscVInstruction::lbu(addr, dst[0], imm)),
        OperandSize::S16 => emit_ins(comp, RiscVInstruction::lhu(addr, dst[0], imm)),
        OperandSize::S32 => emit_ins(comp, RiscVInstruction::lw(addr, dst[0], imm)),
        OperandSize::S64 => emit_ins(comp, RiscVInstruction::lw(addr, dst[0], imm)),
    }
    match size {
        OperandSize::S64 => emit_ins(comp, RiscVInstruction::lw(addr, dst[1], imm + 4)),
        _ => emit_riscv_li(comp, dst[1], 0),
    }
}

#[inline]
fn emit_store_immediate(comp: &mut Compiler, size: OperandSize, addr: Register, imm: i64) {
    emit_riscv_li(comp, RSCRATCH2[0], imm as i32);
    match size {
        OperandSize:: S64 => {
            emit_ins(comp, RiscVInstruction::sw(addr, RSCRATCH2[0], 0));
            emit_riscv_li(comp, RSCRATCH2[0], (imm >> 32) as i32);
            emit_ins(comp, RiscVInstruction::sw(addr, RSCRATCH2[0], 4));
        },
        _ => emit_store(comp, size, addr, [RSCRATCH2[0], Register::X0]),
    }
}

#[inline]
fn emit_store(comp: &mut Compiler, size: OperandSize, addr: Register, src: [Register; 2]) {
    emit_store_offset(comp, size, addr, src, 0);
}

#[inline]
fn emit_store_offset(comp: &mut Compiler, size: OperandSize, addr: Register, src: [Register; 2], imm: i32) {
    match size {
        OperandSize::S0  => {},
        OperandSize::S8  => emit_ins(comp, RiscVInstruction::sb(addr, src[0], imm)),
        OperandSize::S16 => emit_ins(comp, RiscVInstruction::sh(addr, src[0], imm)),
        OperandSize::S32 => emit_ins(comp, RiscVInstruction::sw(addr, src[0], imm)),
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::sw(addr, src[0], imm));
            emit_ins(comp, RiscVInstruction::sw(addr, src[1], imm + 4));
        },
    }
}

#[inline]
fn emit_push(comp: &mut Compiler, src: [Register; 2]) {
    emit_ins(comp, RiscVInstruction::addi(Register::SP, Register::SP, -8));
    emit_store(comp, OperandSize::S64, Register::SP, src);
}

#[allow(dead_code)]
#[inline]
fn emit_pop(comp: &mut Compiler, dst: [Register; 2]) {
    emit_load(comp, OperandSize::S64, Register::SP, dst);
    emit_ins(comp, RiscVInstruction::addi(Register::SP, Register::SP, 8));
}

//#[inline]
//fn emit_push_imm32(comp: &mut Compiler, imm: i32) {
//    emit_riscv_push(comp, Register::X0);
//    emit_riscv_push(comp, RSCRATCH[0]);
//    emit_riscv_li(comp, RSCRATCH[0], imm);
//    emit_ins(comp, RiscVInstruction::sw(Register::SP, RSCRATCH[0], 4));
//    emit_riscv_pop(comp, RSCRATCH[0]);
//}

#[inline]
fn emit_call(comp: &mut Compiler, offset: i32) {
    emit_riscv_push(comp, Register::RA);
    emit_jump(comp, Register::RA, offset);
    emit_riscv_pop(comp, Register::RA);
}

#[allow(dead_code)]
#[inline]
fn emit_call_reg(comp: &mut Compiler, reg: Register) {
    emit_riscv_push(comp, Register::RA);
    emit_ins(comp, RiscVInstruction::jalr(reg, Register::RA, 0));
    emit_riscv_pop(comp, Register::RA);
}

#[inline]
fn emit_return(comp: &mut Compiler) {
    emit_ins(comp, RiscVInstruction::jalr(Register::RA, Register::X0, 0));
}

/*
 * FIXME: The BPF spec states that 32-bit operations should zero-extend their
 * output. However, rbpf appears to be sign-extending. Currently we're
 * zero-extending as per the spec, but this may need to be changed.
 */

#[inline]
fn emit_add(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    emit_ins(comp, RiscVInstruction::add(dst[0], src[0], dst[0]));
    match size {
        OperandSize::S32 => {
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::sltu(dst[0], src[0], RSCRATCH2[0]));
            emit_ins(comp, RiscVInstruction::add(dst[1], src[1], dst[1]));
            emit_ins(comp, RiscVInstruction::add(dst[1], RSCRATCH2[0], dst[1]));
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_sub(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    match size {
        OperandSize::S32 => {
            emit_ins(comp, RiscVInstruction::sub(dst[0], src[0], dst[0]));
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::mv(dst[0], RSCRATCH2[0]));
            emit_ins(comp, RiscVInstruction::sub(dst[0], src[0], dst[0]));
            emit_ins(comp, RiscVInstruction::sltu(RSCRATCH2[0], dst[0], RSCRATCH2[0]));
            emit_ins(comp, RiscVInstruction::sub(dst[1], src[1], dst[1]));
            emit_ins(comp, RiscVInstruction::sub(dst[1], RSCRATCH2[0], dst[1]));
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_mul(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    emit_ins(comp, RiscVInstruction::mul(dst[0], src[0], dst[0]));
    match size {
        OperandSize::S32 => {
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::mul(dst[1], src[0], dst[1]));
            emit_ins(comp, RiscVInstruction::mul(dst[0], src[1], RSCRATCH2[0]));
            emit_ins(comp, RiscVInstruction::add(dst[1], RSCRATCH2[0], dst[1]));
            emit_ins(comp, RiscVInstruction::mulhu(dst[0], src[0], RSCRATCH2[0]));
            emit_ins(comp, RiscVInstruction::mul(dst[0], src[0], dst[0]));
            emit_ins(comp, RiscVInstruction::add(dst[1], RSCRATCH2[0], dst[1]));
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_div(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    match size {
        OperandSize::S32 => {
            emit_ins(comp, RiscVInstruction::divu(dst[0], src[0], dst[0]));
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_c_call(comp, "bpf_div64", &[Value::Register(dst), Value::Register(src)]);
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_sdiv(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    match size {
        OperandSize::S32 => {
            emit_ins(comp, RiscVInstruction::div(dst[0], src[0], dst[0]));
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_c_call(comp, "bpf_sdiv64", &[Value::Register(dst), Value::Register(src)]);
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_mod(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    match size {
        OperandSize::S32 => {
            emit_ins(comp, RiscVInstruction::remu(dst[0], src[0], dst[0]));
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_c_call(comp, "bpf_mod64", &[Value::Register(dst), Value::Register(src)]);
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_or(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    emit_ins(comp, RiscVInstruction::or(src[0], dst[0], dst[0]));
    match size {
        OperandSize::S32 => {
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::or(src[1], dst[1], dst[1]));
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_and(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    emit_ins(comp, RiscVInstruction::and(src[0], dst[0], dst[0]));
    match size {
        OperandSize::S32 => {
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::and(src[1], dst[1], dst[1]));
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_lsh(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    match size {
        OperandSize::S32 => {
            emit_ins(comp, RiscVInstruction::sll(dst[0], src[0], dst[0]));
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_c_call(comp, "bpf_lsh64", &[Value::Register(dst), Value::Register(src)]);
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_rsh(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    match size {
        OperandSize::S32 => {
            emit_ins(comp, RiscVInstruction::srl(dst[0], src[0], dst[0]));
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_c_call(comp, "bpf_rsh64", &[Value::Register(dst), Value::Register(src)]);
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_xor(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    emit_ins(comp, RiscVInstruction::xor(src[0], dst[0], dst[0]));
    match size {
        OperandSize::S32 => {
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::xor(src[1], dst[1], dst[1]));
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_arsh(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    match size {
        OperandSize::S32 => {
            emit_ins(comp, RiscVInstruction::sra(dst[0], src[0], dst[0]));
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_c_call(comp, "bpf_arsh64", &[Value::Register(dst), Value::Register(src)]);
        }
        _ => panic!("unsupported instruction!")
    }
}

macro_rules! make_arith_imm {
    ($name:ident, $name_imm:ident) => {
        #[inline]
        fn $name_imm(comp: &mut Compiler, size: OperandSize, dst: [Register; 2], imm: i64) {
            match size {
                OperandSize::S32 => {
                    emit_riscv_li(comp, RSCRATCH2[0], imm as i32);
                    $name(comp, size, [RSCRATCH2[0], Register::X0], dst);
                },
                OperandSize::S64 => {
                    let scratch0 = if dst[0] == RSCRATCH[0] || dst[1] == RSCRATCH[0] {
                        Register::T3
                    } else {
                        RSCRATCH[0]
                    };
                    let scratch1 = if dst[0] == RSCRATCH[1] || dst[1] == RSCRATCH[1] {
                        Register::T4
                    } else {
                        RSCRATCH[1]
                    };
                    let scratch = [scratch0, scratch1];
                    emit_push(comp, scratch);
                    emit_load_immediate(comp, size, scratch, imm);
                    $name(comp, size, scratch, dst);
                    emit_pop(comp, scratch);
                }
                _ => panic!("unsupported instruction!")
            }
        }
    }
}
make_arith_imm!(emit_add, emit_add_imm);
make_arith_imm!(emit_sub, emit_sub_imm);
make_arith_imm!(emit_mul, emit_mul_imm);
make_arith_imm!(emit_div, emit_div_imm);
make_arith_imm!(emit_sdiv, emit_sdiv_imm);
make_arith_imm!(emit_mod, emit_mod_imm);
make_arith_imm!(emit_or, emit_or_imm);
make_arith_imm!(emit_and, emit_and_imm);
make_arith_imm!(emit_lsh, emit_lsh_imm);
make_arith_imm!(emit_rsh, emit_rsh_imm);
make_arith_imm!(emit_xor, emit_xor_imm);
make_arith_imm!(emit_arsh, emit_arsh_imm);

#[inline]
fn emit_neg(comp: &mut Compiler, size: OperandSize, dst: [Register; 2]) {
    emit_ins(comp, RiscVInstruction::not(dst[0], dst[0]));
    match size {
        OperandSize::S32 => {
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::not(dst[1], dst[1]));
        }
        _ => panic!("unsupported instruction!")
    }
}

#[inline]
fn emit_mov(comp: &mut Compiler, size: OperandSize, src: [Register; 2], dst: [Register; 2]) {
    emit_ins(comp, RiscVInstruction::mv(src[0], dst[0]));
    match size {
        OperandSize::S32 => {
            emit_riscv_li(comp, dst[1], 0);
        }
        OperandSize::S64 => {
            emit_ins(comp, RiscVInstruction::mv(src[1], dst[1]));
        }
        _ => panic!()
    }
}

#[inline]
fn emit_jeq(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_ins(comp, RiscVInstruction::bne(src[0], dst[0], 4 * 4));
    emit_ins(comp, RiscVInstruction::bne(src[1], dst[1], 4 * 3));
    emit_long_jump_to_pc(comp, Register::X0, target_pc); // 2 instructions
}

#[inline]
fn emit_jgt(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_ins(comp, RiscVInstruction::bltu(src[1], dst[1], 4 * 5));
    emit_ins(comp, RiscVInstruction::bne(src[1], dst[1], 4 * 2));
    emit_ins(comp, RiscVInstruction::bleu(src[0], dst[0], 4 * 3));
    emit_long_jump_to_pc(comp, Register::X0, target_pc); // 2 instructions
}

#[inline]
fn emit_jge(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_ins(comp, RiscVInstruction::bltu(src[1], dst[1], 4 * 5));
    emit_ins(comp, RiscVInstruction::bne(src[1], dst[1], 4 * 2));
    emit_ins(comp, RiscVInstruction::bltu(src[0], dst[0], 4 * 3));
    emit_long_jump_to_pc(comp, Register::X0, target_pc); // 2 instructions
}

#[inline]
fn emit_jlt(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_jgt(comp, dst, src, target_pc);
}

#[inline]
fn emit_jle(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_jge(comp, dst, src, target_pc);
}

#[inline]
fn emit_jset(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_ins(comp, RiscVInstruction::and(src[0], dst[0], RSCRATCH2[0]));
    emit_ins(comp, RiscVInstruction::bne(RSCRATCH2[0], Register::X0, 4 * 3));
    emit_ins(comp, RiscVInstruction::and(src[1], dst[1], RSCRATCH2[0]));
    emit_ins(comp, RiscVInstruction::beq(RSCRATCH2[0], Register::X0, 4 * 3));
    emit_long_jump_to_pc(comp, Register::X0, target_pc); // 2 instructions
}

#[inline]
fn emit_jne(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_ins(comp, RiscVInstruction::bne(src[0], dst[0], 4 * 2));
    emit_ins(comp, RiscVInstruction::beq(src[1], dst[1], 4 * 3));
    emit_long_jump_to_pc(comp, Register::X0, target_pc); // 2 instructions
}

#[inline]
fn emit_jsgt(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_ins(comp, RiscVInstruction::blt(src[1], dst[1], 4 * 5));
    emit_ins(comp, RiscVInstruction::bne(src[1], dst[1], 4 * 2));
    emit_ins(comp, RiscVInstruction::bleu(src[0], dst[0], 4 * 3));
    emit_long_jump_to_pc(comp, Register::X0, target_pc); // 2 instructions
}

#[inline]
fn emit_jsge(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_ins(comp, RiscVInstruction::blt(src[1], dst[1], 4 * 5));
    emit_ins(comp, RiscVInstruction::bne(src[1], dst[1], 4 * 2));
    emit_ins(comp, RiscVInstruction::bltu(src[0], dst[0], 4 * 3));
    emit_long_jump_to_pc(comp, Register::X0, target_pc); // 2 instructions
}

#[inline]
fn emit_jslt(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_jsgt(comp, dst, src, target_pc);
}

#[inline]
fn emit_jsle(comp: &mut Compiler, src: [Register; 2], dst: [Register; 2], target_pc: usize) {
    emit_jsge(comp, dst, src, target_pc);
}

macro_rules! make_jmp_imm {
    ($name:ident, $name_imm:ident) => {
        #[inline]
        fn $name_imm(comp: &mut Compiler, dst: [Register; 2], imm: i64, target_pc: usize) {
            emit_load_immediate(comp, OperandSize::S64, RSCRATCH, imm);
            $name(comp, RSCRATCH, dst, target_pc);
        }
    }
}

make_jmp_imm!(emit_jeq, emit_jeq_imm);
make_jmp_imm!(emit_jgt, emit_jgt_imm);
make_jmp_imm!(emit_jge, emit_jge_imm);
make_jmp_imm!(emit_jlt, emit_jlt_imm);
make_jmp_imm!(emit_jle, emit_jle_imm);
make_jmp_imm!(emit_jset, emit_jset_imm);
make_jmp_imm!(emit_jne, emit_jne_imm);
make_jmp_imm!(emit_jsgt, emit_jsgt_imm);
make_jmp_imm!(emit_jsge, emit_jsge_imm);
make_jmp_imm!(emit_jslt, emit_jslt_imm);
make_jmp_imm!(emit_jsle, emit_jsle_imm);

#[derive(Debug)]
struct Jump {
    location: *const u8,
    target_pc: usize,
}

pub enum RiscVRelocation {
    Call {
        offset: usize,
        symbol: &'static str,
    },
    Hi20 {
        offset: usize,
        symbol: &'static str,
    },
    Lo12I {
        offset: usize,
        symbol: &'static str,
    },
}

#[allow(dead_code)]
pub struct Compiler {
    pub result: ProgramSections,
    pub pc_offsets : Vec<u32>,
    text_section_jumps: Vec<Jump>,
    pub relocations: Vec<RiscVRelocation>,
    offset_in_text_section: usize,
    pc: usize,
    last_instruction_meter_validation_pc: usize,
    next_noop_insertion: u32,
    program_vm_addr: u64,
    anchors: [*const u8; ANCHOR_COUNT],
    anchor_offsets: [usize; ANCHOR_COUNT],
    pub(crate) config: Config,
    diversification_rng: SmallRng,
    stopwatch_is_active: bool,
    environment_stack_key: i32,
    program_argument_key: i32,
    err_kind_offset: usize,
}

impl Index<usize> for Compiler {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &self.result.text_section[_index]
    }
}

impl IndexMut<usize> for Compiler {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        &mut self.result.text_section[_index]
    }
}

impl std::fmt::Debug for Compiler {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FormatterError> {
        fmt.write_str("JIT text_section: [")?;
        for i in self.result.text_section as &[u8] {
            fmt.write_fmt(format_args!(" {:#04x},", i))?;
        };
        fmt.write_str(" ] | ")?;
        fmt.debug_struct("JIT state")
            .field("memory", &self.result.pc_section.as_ptr())
            .field("pc", &self.pc)
            .field("offset_in_text_section", &self.offset_in_text_section)
            .field("pc_section", &self.result.pc_section)
            .field("anchors", &self.anchors)
            .field("text_section_jumps", &self.text_section_jumps)
            .finish()
    }
}

impl Compiler {
    // Arguments are unused on windows
    pub fn new<E: UserDefinedError>(program: &[u8], config: &Config) -> Result<Self, EbpfError<E>> {
        // Scan through program to find actual number of instructions
        let mut pc = 0;
        while (pc + 1) * ebpf::INSN_SIZE <= program.len() {
            let insn = ebpf::get_insn_unchecked(program, pc);
            pc += match insn.opc {
                ebpf::LD_DW_IMM => 2,
                _ => 1,
            };
        }

        let mut code_length_estimate = MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION * pc;
        if config.noop_instruction_rate != 0 {
            code_length_estimate += code_length_estimate / config.noop_instruction_rate as usize;
        }
        if config.instruction_meter_checkpoint_distance != 0 {
            code_length_estimate += pc / config.instruction_meter_checkpoint_distance * MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT;
        }
        let result = ProgramSections::new(pc + 1, code_length_estimate)?;
        let pc_offsets = vec![0; pc + 1];

        let mut diversification_rng = SmallRng::from_rng(rand::thread_rng()).unwrap();
        let (environment_stack_key, program_argument_key) =
            if config.encrypt_environment_registers {
                (
                    diversification_rng.gen::<i32>() / 16, // -3 bits for 8 Byte alignment, and -1 bit to have encoding space for EnvironmentStackSlot::SlotCount
                    diversification_rng.gen::<i32>() / 2, // -1 bit to have encoding space for (ProgramEnvironment::SYSCALLS_OFFSET + syscall.context_object_slot) * 8
                )
            } else { (0, 0) };

        let ok = Result::<u64, EbpfError<E>>::Ok(0);
        let is_err = unsafe { *(&ok as *const _ as *const u64) };

        Ok(Self {
            result,
            pc_offsets,
            text_section_jumps: vec![],
            relocations: vec![],
            offset_in_text_section: 0,
            pc: 0,
            last_instruction_meter_validation_pc: 0,
            next_noop_insertion: if config.noop_instruction_rate == 0 { u32::MAX } else { diversification_rng.gen_range(0..config.noop_instruction_rate * 2) },
            program_vm_addr: 0,
            anchors: [std::ptr::null(); ANCHOR_COUNT],
            anchor_offsets: [0; ANCHOR_COUNT],
            config: *config,
            diversification_rng,
            stopwatch_is_active: false,
            environment_stack_key,
            program_argument_key,
            err_kind_offset: (is_err == 0) as usize,
        })
    }

    pub fn compile<E: UserDefinedError, I: InstructionMeter>(&mut self,
            executable: &Executable<E, I>) -> Result<(), EbpfError<E>> {
        let (program_vm_addr, program) = executable.get_text_bytes();
        self.program_vm_addr = program_vm_addr;

        self.generate_prologue::<E, I>(executable)?;

        // Have these in front so that the linear search of ANCHOR_TRANSLATE_PC does not terminate early
        self.generate_subroutines::<E, I>()?;

        while self.pc * ebpf::INSN_SIZE < program.len() {
            if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION > self.result.text_section.len() {
                return Err(EbpfError::ExhaustedTextSegment(self.pc));
            }
            let mut insn = ebpf::get_insn_unchecked(program, self.pc);
            self.add_to_pc_section(self.offset_in_text_section);

            // Regular instruction meter checkpoints to prevent long linear runs from exceeding their budget
            if self.last_instruction_meter_validation_pc + self.config.instruction_meter_checkpoint_distance <= self.pc {
                emit_validate_instruction_count(self, true, Some(self.pc));
            }

            let dst = if insn.dst == STACK_PTR_REG as u8 { RZERO } else { REGISTER_MAP[insn.dst as usize] };
            let src = REGISTER_MAP[insn.src as usize];
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;

            match insn.opc {
                _ if insn.dst == STACK_PTR_REG as u8 && self.config.dynamic_stack_frames => {
                    let stack_ptr_offset = slot_on_environment_stack(self, EnvironmentStackSlot::BpfStackPtr);
                    emit_load_offset(self, OperandSize::S64, Register::T6, RSCRATCH, stack_ptr_offset);
                    match insn.opc {
                        ebpf::SUB64_IMM => emit_sub_imm(self, OperandSize::S64, RSCRATCH, insn.imm),
                        ebpf::ADD64_IMM => emit_add_imm(self, OperandSize::S64, RSCRATCH, insn.imm),
                        _ => {
                            #[cfg(debug_assertions)]
                            unreachable!("unexpected insn on r11")
                        }
                    }
                    emit_store_offset(self, OperandSize::S64, Register::T6, RSCRATCH, stack_ptr_offset);
                }

                ebpf::LD_DW_IMM  => {
                    emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2));
                    self.pc += 1;
                    self.add_to_pc_section(self.anchor_offsets[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION]);
                    ebpf::augment_lddw_unchecked(program, &mut insn);
                    emit_load_immediate(self, OperandSize::S64, dst, insn.imm);
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(src, insn.off as i64, true));
                    emit_load(self, OperandSize::S8, RSCRATCH[0], dst);
                },
                ebpf::LD_H_REG   => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(src, insn.off as i64, true));
                    emit_load(self, OperandSize::S16, RSCRATCH[0], dst);
                },
                ebpf::LD_W_REG   => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(src, insn.off as i64, true));
                    emit_load(self, OperandSize::S32, RSCRATCH[0], dst);
                },
                ebpf::LD_DW_REG  => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(src, insn.off as i64, true));
                    emit_load(self, OperandSize::S64, RSCRATCH[0], dst);
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(dst, insn.off as i64, true));
                    emit_store_immediate(self, OperandSize::S8, RSCRATCH[0], insn.imm as i64);
                },
                ebpf::ST_H_IMM   => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(dst, insn.off as i64, true));
                    emit_store_immediate(self, OperandSize::S16, RSCRATCH[0], insn.imm as i64);
                },
                ebpf::ST_W_IMM   => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(dst, insn.off as i64, true));
                    emit_store_immediate(self, OperandSize::S32, RSCRATCH[0], insn.imm as i64);
                },
                ebpf::ST_DW_IMM  => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(dst, insn.off as i64, true));
                    emit_store_immediate(self, OperandSize::S64, RSCRATCH[0], insn.imm as i64);
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(dst, insn.off as i64, true));
                    emit_store(self, OperandSize::S8, RSCRATCH[0], src);
                },
                ebpf::ST_H_REG  => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(dst, insn.off as i64, true));
                    emit_store(self, OperandSize::S16, RSCRATCH[0], src);
                },
                ebpf::ST_W_REG  => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(dst, insn.off as i64, true));
                    emit_store(self, OperandSize::S32, RSCRATCH[0], src);
                },
                ebpf::ST_DW_REG  => {
                    emit_address_translation(self, Value::RegisterPlusConstant64(dst, insn.off as i64, true));
                    emit_store(self, OperandSize::S64, RSCRATCH[0], src);
                },

                // BPF_ALU class
                ebpf::ADD32_REG  => emit_add(self, OperandSize::S32, src, dst),
                ebpf::SUB32_REG  => emit_sub(self, OperandSize::S32, src, dst),
                ebpf::MUL32_REG  => emit_mul(self, OperandSize::S32, src, dst),
                ebpf::DIV32_REG  => emit_div(self, OperandSize::S32, src, dst),
                ebpf::SDIV32_REG => emit_sdiv(self, OperandSize::S32, src, dst),
                ebpf::MOD32_REG  => emit_mod(self, OperandSize::S32, src, dst),
                ebpf::OR32_REG   => emit_or(self, OperandSize::S32, src, dst),
                ebpf::AND32_REG  => emit_and(self, OperandSize::S32, src, dst),
                ebpf::LSH32_REG  => emit_lsh(self, OperandSize::S32, src, dst),
                ebpf::RSH32_REG  => emit_rsh(self, OperandSize::S32, src, dst),
                ebpf::NEG32      => emit_neg(self, OperandSize::S32, dst),
                ebpf::XOR32_REG  => emit_xor(self, OperandSize::S32, src, dst),
                ebpf::MOV32_REG  => emit_mov(self, OperandSize::S32, src, dst),
                ebpf::ARSH32_REG => emit_arsh(self, OperandSize::S32, src, dst),
                ebpf::ADD32_IMM  => emit_add_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::SUB32_IMM  => emit_sub_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::MUL32_IMM  => emit_mul_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::DIV32_IMM  => emit_div_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::SDIV32_IMM => emit_sdiv_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::MOD32_IMM  => emit_mod_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::OR32_IMM   => emit_or_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::AND32_IMM  => emit_and_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::LSH32_IMM  => emit_lsh_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::RSH32_IMM  => emit_rsh_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::XOR32_IMM  => emit_xor_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::MOV32_IMM  => emit_load_immediate(self, OperandSize::S32, dst, insn.imm),
                ebpf::ARSH32_IMM => emit_arsh_imm(self, OperandSize::S32, dst, insn.imm),
                ebpf::LE         => {
                    match insn.imm {
                        16 => {
                            // Mask to 16 bit
                            emit_riscv_li(self, RSCRATCH[0], 0xffff);
                            emit_and(self, OperandSize::S32, [RSCRATCH[0], Register::X0], dst);
                        }
                        32 => {
                            // Mask to 32 bit
                            emit_riscv_li(self, dst[1], 0);
                        }
                        64 => {}
                        _ => {
                            return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            emit_ins(self, RiscVInstruction::xori(dst[0], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::srli(dst[0], dst[0], 8));
                            emit_ins(self, RiscVInstruction::xori(dst[0], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::slli(RSCRATCH[0], RSCRATCH[0], 8));
                            emit_ins(self, RiscVInstruction::or(dst[0], RSCRATCH[0], dst[0]));

                            // zero top 32 bits
                            emit_riscv_li(self, dst[1], 0);
                        }
                        32 => {
                            // copy top two bytes to RSCRATCH[1]
                            emit_ins(self, RiscVInstruction::srli(dst[0], RSCRATCH[1], 16));

                            // swap bottom two bytes
                            emit_ins(self, RiscVInstruction::xori(dst[0], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::srli(dst[0], dst[0], 8));
                            emit_ins(self, RiscVInstruction::xori(dst[0], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::slli(RSCRATCH[0], RSCRATCH[0], 8));
                            emit_ins(self, RiscVInstruction::or(dst[0], RSCRATCH[0], dst[0]));

                            // swap top two bytes
                            emit_ins(self, RiscVInstruction::xori(RSCRATCH[1], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::srli(RSCRATCH[1], RSCRATCH[1], 8));
                            emit_ins(self, RiscVInstruction::xori(RSCRATCH[1], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::slli(RSCRATCH[0], RSCRATCH[0], 8));
                            emit_ins(self, RiscVInstruction::or(RSCRATCH[1], RSCRATCH[0], RSCRATCH[1]));

                            // merge top and bottom
                            emit_ins(self, RiscVInstruction::slli(dst[0], dst[0], 16));
                            emit_ins(self, RiscVInstruction::or(dst[0], RSCRATCH[1], dst[0]));

                            // zero top 32 bits
                            emit_riscv_li(self, dst[1], 0);
                        },
                        64 => {
                            // do the above for the bottom 32 bits, storing the result in RSCRATCH2[0]
                            emit_ins(self, RiscVInstruction::srli(dst[0], RSCRATCH[1], 16));

                            emit_ins(self, RiscVInstruction::xori(dst[0], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::srli(dst[0], dst[0], 8));
                            emit_ins(self, RiscVInstruction::xori(dst[0], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::slli(RSCRATCH[0], RSCRATCH[0], 8));
                            emit_ins(self, RiscVInstruction::or(dst[0], RSCRATCH[0], dst[0]));

                            emit_ins(self, RiscVInstruction::xori(RSCRATCH[1], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::srli(RSCRATCH[1], RSCRATCH[1], 8));
                            emit_ins(self, RiscVInstruction::xori(RSCRATCH[1], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::slli(RSCRATCH[0], RSCRATCH[0], 8));
                            emit_ins(self, RiscVInstruction::or(RSCRATCH[1], RSCRATCH[0], RSCRATCH[1]));

                            emit_ins(self, RiscVInstruction::slli(dst[0], dst[0], 16));
                            emit_ins(self, RiscVInstruction::or(dst[0], RSCRATCH[1], RSCRATCH2[0]));

                            // and now the top 32 bits, into dst[0]
                            emit_ins(self, RiscVInstruction::srli(dst[1], RSCRATCH[1], 16));

                            emit_ins(self, RiscVInstruction::xori(dst[1], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::srli(dst[1], dst[1], 8));
                            emit_ins(self, RiscVInstruction::xori(dst[1], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::slli(RSCRATCH[0], RSCRATCH[0], 8));
                            emit_ins(self, RiscVInstruction::or(dst[1], RSCRATCH[0], dst[1]));

                            emit_ins(self, RiscVInstruction::xori(RSCRATCH[1], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::srli(RSCRATCH[1], RSCRATCH[1], 8));
                            emit_ins(self, RiscVInstruction::xori(RSCRATCH[1], RSCRATCH[0], 0xff));
                            emit_ins(self, RiscVInstruction::slli(RSCRATCH[0], RSCRATCH[0], 8));
                            emit_ins(self, RiscVInstruction::or(RSCRATCH[1], RSCRATCH[0], RSCRATCH[1]));

                            emit_ins(self, RiscVInstruction::slli(dst[1], dst[1], 16));
                            emit_ins(self, RiscVInstruction::or(dst[1], RSCRATCH[1], dst[0]));

                            // finish the dword swap
                            emit_ins(self, RiscVInstruction::mv(RSCRATCH2[0], dst[1]));
                        },
                        _ => {
                            return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_REG  => emit_add(self, OperandSize::S64, src, dst),
                ebpf::SUB64_REG  => emit_sub(self, OperandSize::S64, src, dst),
                ebpf::MUL64_REG  => emit_mul(self, OperandSize::S64, src, dst),
                ebpf::DIV64_REG  => emit_div(self, OperandSize::S64, src, dst),
                ebpf::SDIV64_REG => emit_sdiv(self, OperandSize::S64, src, dst),
                ebpf::MOD64_REG  => emit_mod(self, OperandSize::S64, src, dst),
                ebpf::OR64_REG   => emit_or(self, OperandSize::S64, src, dst),
                ebpf::AND64_REG  => emit_and(self, OperandSize::S64, src, dst),
                ebpf::LSH64_REG  => emit_lsh(self, OperandSize::S64, src, dst),
                ebpf::RSH64_REG  => emit_rsh(self, OperandSize::S64, src, dst),
                ebpf::NEG64      => emit_neg(self, OperandSize::S64, dst),
                ebpf::XOR64_REG  => emit_xor(self, OperandSize::S64, src, dst),
                ebpf::MOV64_REG  => emit_mov(self, OperandSize::S64, src, dst),
                ebpf::ARSH64_REG => emit_arsh(self, OperandSize::S64, src, dst),
                ebpf::ADD64_IMM  => emit_add_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::SUB64_IMM  => emit_sub_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::MUL64_IMM  => emit_mul_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::DIV64_IMM  => emit_div_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::SDIV64_IMM => emit_sdiv_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::MOD64_IMM  => emit_mod_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::OR64_IMM   => emit_or_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::AND64_IMM  => emit_and_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::LSH64_IMM  => emit_lsh_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::RSH64_IMM  => emit_rsh_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::XOR64_IMM  => emit_xor_imm(self, OperandSize::S64, dst, insn.imm),
                ebpf::MOV64_IMM  => emit_load_immediate(self, OperandSize::S64, dst, insn.imm),
                ebpf::ARSH64_IMM => emit_arsh_imm(self, OperandSize::S64, dst, insn.imm),

                // BPF_JMP class
                ebpf::JA         => {
                    emit_validate_and_profile_instruction_count(self, false, Some(target_pc));
                    // unclear what this load is for
                    emit_load_immediate(self, OperandSize::S64, RSCRATCH, target_pc as i64);
                    emit_jump_to_pc(self, Register::X0, target_pc);
                },
                ebpf::JEQ_REG    => emit_jeq(self, src, dst, target_pc),
                ebpf::JGT_REG    => emit_jgt(self, src, dst, target_pc),
                ebpf::JGE_REG    => emit_jge(self, src, dst, target_pc),
                ebpf::JLT_REG    => emit_jlt(self, src, dst, target_pc),
                ebpf::JLE_REG    => emit_jle(self, src, dst, target_pc),
                ebpf::JSET_REG   => emit_jset(self, src, dst, target_pc),
                ebpf::JNE_REG    => emit_jne(self, src, dst, target_pc),
                ebpf::JSGT_REG   => emit_jsgt(self, src, dst, target_pc),
                ebpf::JSGE_REG   => emit_jsge(self, src, dst, target_pc),
                ebpf::JSLT_REG   => emit_jslt(self, src, dst, target_pc),
                ebpf::JSLE_REG   => emit_jsle(self, src, dst, target_pc),
                ebpf::JEQ_IMM    => emit_jeq_imm(self, dst, insn.imm, target_pc),
                ebpf::JGT_IMM    => emit_jgt_imm(self, dst, insn.imm, target_pc),
                ebpf::JGE_IMM    => emit_jge_imm(self, dst, insn.imm, target_pc),
                ebpf::JLT_IMM    => emit_jlt_imm(self, dst, insn.imm, target_pc),
                ebpf::JLE_IMM    => emit_jle_imm(self, dst, insn.imm, target_pc),
                ebpf::JSET_IMM   => emit_jset_imm(self, dst, insn.imm, target_pc),
                ebpf::JNE_IMM    => emit_jne_imm(self, dst, insn.imm, target_pc),
                ebpf::JSGT_IMM   => emit_jsgt_imm(self, dst, insn.imm, target_pc),
                ebpf::JSGE_IMM   => emit_jsge_imm(self, dst, insn.imm, target_pc),
                ebpf::JSLT_IMM   => emit_jslt_imm(self, dst, insn.imm, target_pc),
                ebpf::JSLE_IMM   => emit_jsle_imm(self, dst, insn.imm, target_pc),

                ebpf::CALL_IMM   => {
                    // For JIT, syscalls MUST be registered at compile time. They can be
                    // updated later, but not created after compiling (we need the address of the
                    // syscall function in the JIT-compiled program).

                    let mut resolved = false;
                    let (_syscalls, calls) = if self.config.static_syscalls {
                        (insn.src == 0, insn.src != 0)
                    } else {
                        (true, true)
                    };

                    // TODO implement syscalls
//                  if syscalls {
//                      if let Some(syscall) = executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
//                          if self.config.enable_instruction_meter {
//                              emit_validate_and_profile_instruction_count(self, true, Some(0));
//                          }
//                          emit_load_immediate(self, OperandSize::S64, RSCRATCH, syscall.function as *const u8 as i64);
//                          emit_ins(self, RiscVInstruction::load(OperandSize::S64, R10, RAX, X86IndirectAccess::Offset(ProgramEnvironment::SYSCALLS_OFFSET as i32 + syscall.context_object_slot as i32 * 8 + self.program_argument_key)));
//                          emit_call(self, self.relative_to_anchor(ANCHOR_SYSCALL));
//                          if self.config.enable_instruction_meter {
//                              emit_undo_profile_instruction_count(self, 0);
//                          }
//                          resolved = true;
//                      }
//                  }

                    if calls {
                        if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                            emit_bpf_call(self, Value::Constant64(target_pc as i64, false));
                            resolved = true;
                        }
                    }

                    if !resolved {
                        emit_load_immediate(self, OperandSize::S64, RSCRATCH, self.pc as i64);
                        emit_jump_to_anchor(self, Register::X0, ANCHOR_CALL_UNSUPPORTED_INSTRUCTION);
                    }
                },
                ebpf::CALL_REG  => {
                    emit_bpf_call(self, Value::Register(REGISTER_MAP[insn.imm as usize]));
                },
                ebpf::EXIT      => {
                    let call_depth_offset = slot_on_environment_stack(self, EnvironmentStackSlot::CallDepth);
                    // we only need the lower 32 bits of this since the max call depth is 32 bits
                    emit_ins(self, RiscVInstruction::lw(Register::T6, REGISTER_MAP[FRAME_PTR_REG][0], call_depth_offset));

                    // If CallDepth == 0, we've reached the exit instruction of the entry point
                    if self.config.enable_instruction_meter {
                        emit_ins(self, RiscVInstruction::bne(REGISTER_MAP[FRAME_PTR_REG][0], Register::X0, 4 * 6));
                        // manually load so that we know how many instructions to jump
                        emit_riscv_li_controlled(self, RSCRATCH[0], self.pc as i32, true); // 2 instructions
                        emit_riscv_li_controlled(self, RSCRATCH[1], (self.pc >> 32) as i32, true); // 2
                    } else {
                        emit_ins(self, RiscVInstruction::bne(REGISTER_MAP[FRAME_PTR_REG][0], Register::X0, 4 * 2));
                    }
                    // we're done
                    emit_long_jump_to_anchor(self, Register::X0, ANCHOR_EXIT); // 2

                    // else decrement and update CallDepth
                    emit_ins(self, RiscVInstruction::addi(REGISTER_MAP[FRAME_PTR_REG][0], REGISTER_MAP[FRAME_PTR_REG][0], -1));
                    emit_ins(self, RiscVInstruction::sw(Register::T6, REGISTER_MAP[FRAME_PTR_REG][0], call_depth_offset));

                    // and return
                    emit_validate_and_profile_instruction_count(self, false, Some(0));
                    emit_return(self);
                },

                _               => return Err(EbpfError::UnsupportedInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }

            self.pc += 1;
        }
        // Bumper so that the linear search of ANCHOR_TRANSLATE_PC can not run off
        self.add_to_pc_section(self.offset_in_text_section);

        // Bumper in case there was no final exit
        if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION > self.result.text_section.len() {
            return Err(EbpfError::ExhaustedTextSegment(self.pc));
        }
        emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2));
        emit_load_immediate(self, OperandSize::S64, RSCRATCH, self.pc as i64);
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EXCEPTION_AT);

        self.resolve_jumps();
        self.result.seal(self.offset_in_text_section)?;

        // Delete secrets
        self.environment_stack_key = 0;
        self.program_argument_key = 0;

        Ok(())
    }

    fn generate_prologue<E: UserDefinedError, I: InstructionMeter>(&mut self, executable: &Executable<E, I>) -> Result<(), EbpfError<E>> {
        // Place the environment on the stack according to EnvironmentStackSlot

        // Save registers
        for reg in CALLEE_SAVED_REGISTERS.iter() {
            if *reg != Register::SP {
                emit_riscv_push(self, *reg);
            }
        }

        // Initialize CallDepth to 0
        emit_push(self, [Register::X0, Register::X0]);

        // Initialize the BPF frame and stack pointers (BpfFramePtr and BpfStackPtr)
        if self.config.dynamic_stack_frames {
            // The stack is fully descending from MM_STACK_START + stack_size to MM_STACK_START
            emit_load_immediate(self, OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START as i64 + self.config.stack_size() as i64);
            // Push BpfFramePtr
            emit_push(self, REGISTER_MAP[FRAME_PTR_REG]);
            // Push BpfStackPtr
            emit_push(self, REGISTER_MAP[FRAME_PTR_REG]);
        } else {
            // The frames are ascending from MM_STACK_START to MM_STACK_START + stack_size. The stack within the frames is descending.
            emit_load_immediate(self, OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START as i64 + self.config.stack_frame_size as i64);
            // Push BpfFramePtr
            emit_push(self, REGISTER_MAP[FRAME_PTR_REG]);
            // When using static frames BpfStackPtr is not used
            emit_riscv_li(self, Register::T6, 0);
            emit_push(self, [Register::T6, Register::X0]);
        }

        // Save pointer to optional typed return value
        emit_push(self, [ARGUMENT_REGISTERS[0], Register::X0]);

        // TODO Save initial value of instruction_meter.get_remaining()
        emit_push(self, [Register::X0, Register::X0]);

        // TODO Save instruction meter
        emit_push(self, [Register::X0, Register::X0]);

        // Initialize stop watch
        emit_push(self, [Register::X0, Register::X0]);
        emit_push(self, [Register::X0, Register::X0]);

        // Initialize frame pointer
        emit_riscv_li(self, Register::T6, 8 * (EnvironmentStackSlot::SlotCount as i32 - 1 + self.environment_stack_key as i32));
        emit_ins(self, RiscVInstruction::add(Register::SP, Register::T6, Register::T6));

        // Zero BPF registers
        for reg in REGISTER_MAP.iter() {
            if *reg != REGISTER_MAP[1] && *reg != REGISTER_MAP[FRAME_PTR_REG] {
                emit_ins(self, RiscVInstruction::mv(Register::X0, reg[0]));
                emit_ins(self, RiscVInstruction::mv(Register::X0, reg[1]));
            }
        }

        // Jump to entry point
        let entry = executable.get_entrypoint_instruction_offset().unwrap_or(0);
        if self.config.enable_instruction_meter {
            emit_profile_instruction_count(self, Some(entry + 1));
        }
        emit_load_immediate(self, OperandSize::S64, RSCRATCH, entry as i64);
        emit_jump_to_pc(self, Register::X0, entry);

        Ok(())
    }

    fn generate_subroutines<E: UserDefinedError, I: InstructionMeter>(&mut self) -> Result<(), EbpfError<E>> {
        // Epilogue
        self.set_anchor(ANCHOR_EPILOGUE);
        // Print stop watch value
//      fn stopwatch_result(numerator: u64, denominator: u64) {
//          println!("Stop watch: {} / {} = {}", numerator, denominator, if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 });
//      }
//      if self.stopwatch_is_active {
//          emit_rust_call(self, Value::Constant64(stopwatch_result as *const u8 as i64, false), &[
//              Argument { index: 1, value: Value::RegisterIndirect(Register::T6, slot_on_environment_stack(self, EnvironmentStackSlot::StopwatchDenominator), false) },
//              Argument { index: 0, value: Value::RegisterIndirect(Register::T6, slot_on_environment_stack(self, EnvironmentStackSlot::StopwatchNumerator), false) },
//          ], None);
//      }
        // Store instruction_meter in RAX
//      emit_ins(self, RiscVInstruction::mv(OperandSize::S64, ARGUMENT_REGISTERS[0], RAX));
        // Restore stack pointer
        emit_ins(self, RiscVInstruction::addi(Register::T6, Register::SP, slot_on_environment_stack(self, EnvironmentStackSlot::LastSavedRegister)));
        // Save BPF registers for use by the wrapper
        emit_address_translation(self, Value::Constant64(0x200000000, false));
        for reg in REGISTER_MAP.iter() {
            emit_store(self, OperandSize::S64, RSCRATCH[0], *reg);
            emit_ins(self, RiscVInstruction::addi(RSCRATCH[0], RSCRATCH[0], 8));
        }
        // Restore registers
        for reg in CALLEE_SAVED_REGISTERS.iter().rev() {
            if *reg != Register::SP {
                emit_riscv_pop(self, *reg);
            }
        }
        emit_return(self);

        // Routine for instruction tracing
        if self.config.enable_instruction_tracing {
            self.set_anchor(ANCHOR_TRACE);
            // Save registers on stack
//          emit_push(self, RSCRATCH);
//          for reg in REGISTER_MAP.iter().rev() {
//              emit_push(self, *reg);
//          }
//          emit_ins(self, RiscVInstruction::mov(OperandSize::S64, Register::SP, REGISTER_MAP[0]));
//          emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, Register::SP, - 8 * 3, None)); // Register::SP -= 8 * 3;
//          emit_rust_call(self, Value::Constant64(Tracer::trace as *const u8 as i64, false), &[
//              Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
//              Argument { index: 0, value: Value::RegisterPlusConstant32(R10, ProgramEnvironment::TRACER_OFFSET as i32 + self.program_argument_key, false) }, // jit.tracer
//          ], None);
//          // Pop stack and return
//          emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, Register::SP, 8 * 3, None)); // Register::SP += 8 * 3;
//          emit_pop(self, REGISTER_MAP[0]);
//          emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, Register::SP, 8 * (REGISTER_MAP.len() - 1) as i64, None)); // Register::SP += 8 * (REGISTER_MAP.len() - 1);
//          emit_pop(self, RSCRATCH);
//          emit_return(self);
        }

        // Handler for syscall exceptions
        self.set_anchor(ANCHOR_RUST_EXCEPTION);
        emit_profile_instruction_count_finalize(self, false);
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EPILOGUE);

        // Handler for EbpfError::ExceededMaxInstructions
        self.set_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS);
//      emit_set_exception_kind::<E>(self, EbpfError::ExceededMaxInstructions(0, 0));
        emit_mov(self, OperandSize::S64, [ARGUMENT_REGISTERS[0], Register::X0], RSCRATCH); // RSCRATCH = instruction_meter;
        emit_profile_instruction_count_finalize(self, true);
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EPILOGUE);

        // Handler for exceptions which report their pc
        self.set_anchor(ANCHOR_EXCEPTION_AT);
        // Validate that we did not reach the instruction meter limit before the exception occured
        if self.config.enable_instruction_meter {
            emit_validate_instruction_count(self, false, None);
        }
        emit_profile_instruction_count_finalize(self, true);
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EPILOGUE);

        // Handler for EbpfError::CallDepthExceeded
        self.set_anchor(ANCHOR_CALL_DEPTH_EXCEEDED);
//      emit_set_exception_kind::<E>(self, EbpfError::CallDepthExceeded(0, 0));
//      emit_ins(self, RiscVInstruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset((std::mem::size_of::<u64>() * (self.err_kind_offset + 2)) as i32), self.config.max_call_depth as i64)); // depth = jit.config.max_call_depth;
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EXCEPTION_AT);

        // Handler for EbpfError::CallOutsideTextSegment
        self.set_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT);
//      emit_set_exception_kind::<E>(self, EbpfError::CallOutsideTextSegment(0, 0));
//      emit_ins(self, RiscVInstruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset((std::mem::size_of::<u64>() * (self.err_kind_offset + 2)) as i32))); // target_address = RAX;
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EXCEPTION_AT);

        // Handler for EbpfError::DivideByZero
        self.set_anchor(ANCHOR_DIV_BY_ZERO);
//      emit_set_exception_kind::<E>(self, EbpfError::DivideByZero(0));
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EXCEPTION_AT);

        // Handler for EbpfError::DivideOverflow
        self.set_anchor(ANCHOR_DIV_OVERFLOW);
//      emit_set_exception_kind::<E>(self, EbpfError::DivideOverflow(0));
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EXCEPTION_AT);

        // Handler for EbpfError::UnsupportedInstruction
        self.set_anchor(ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION);
        // Load BPF target pc from stack (which was saved in ANCHOR_BPF_CALL_REG)
//      emit_ins(self, RiscVInstruction::load(OperandSize::S64, Register::SP, RSCRATCH, X86IndirectAccess::OffsetIndexShift(-16, Register::SP, 0))); // RSCRATCH = Register::SP[-16];
        // emit_jump_to_anchor(self, Register::X0, ANCHOR_CALL_UNSUPPORTED_INSTRUCTION); // Fall-through

        // Handler for EbpfError::UnsupportedInstruction
        self.set_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION);
        if self.config.enable_instruction_tracing {
            emit_call(self, self.relative_to_anchor(ANCHOR_TRACE));
        }
//      emit_set_exception_kind::<E>(self, EbpfError::UnsupportedInstruction(0));
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EXCEPTION_AT);

        // Quit gracefully
        self.set_anchor(ANCHOR_EXIT);
        emit_validate_instruction_count(self, false, None);
        emit_profile_instruction_count_finalize(self, false);
//      emit_ins(self, RiscVInstruction::load(OperandSize::S64, Register::T6, R10, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr))));
//      emit_ins(self, RiscVInstruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(8))); // result.return_value = R0;
        emit_jump_to_anchor(self, Register::X0, ANCHOR_EPILOGUE);

        // Routine for syscall
        self.set_anchor(ANCHOR_SYSCALL);
//      emit_push(self, RSCRATCH); // Padding for stack alignment
//      if self.config.enable_instruction_meter {
//          // RDI = *PrevInsnMeter - RDI;
//          emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x2B, ARGUMENT_REGISTERS[0], Register::T6, 0, Some(X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::PrevInsnMeter))))); // RDI -= *PrevInsnMeter;
//          emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0xf7, 3, ARGUMENT_REGISTERS[0], 0, None)); // RDI = -RDI;
//          emit_rust_call(self, Value::Constant64(I::consume as *const u8 as i64, false), &[
//              Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[0]) },
//              Argument { index: 0, value: Value::RegisterIndirect(Register::T6, slot_on_environment_stack(self, EnvironmentStackSlot::InsnMeterPtr), false) },
//          ], None);
//      }
//      emit_rust_call(self, Value::Register(RSCRATCH), &[
//          Argument { index: 7, value: Value::RegisterIndirect(Register::T6, slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr), false) },
//          Argument { index: 6, value: Value::RegisterPlusConstant32(R10, self.program_argument_key, false) }, // jit_program_argument.memory_mapping
//          Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
//          Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
//          Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
//          Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
//          Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
//          Argument { index: 0, value: Value::Register(RAX) }, // "&mut self" in the "call" method of the SyscallObject
//      ], None);
//      if self.config.enable_instruction_meter {
//          emit_rust_call(self, Value::Constant64(I::get_remaining as *const u8 as i64, false), &[
//              Argument { index: 0, value: Value::RegisterIndirect(Register::T6, slot_on_environment_stack(self, EnvironmentStackSlot::InsnMeterPtr), false) },
//          ], Some(ARGUMENT_REGISTERS[0]));
//          emit_ins(self, RiscVInstruction::store(OperandSize::S64, ARGUMENT_REGISTERS[0], Register::T6, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::PrevInsnMeter))));
//      }

//      // Test if result indicates that an error occured
//      emit_result_is_err::<E>(self, Register::T6, RSCRATCH, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr)));
//      emit_ins(self, RiscVInstruction::conditional_jump_immediate(0x85, self.relative_to_anchor(ANCHOR_RUST_EXCEPTION)));
//      // Store Ok value in result register
//      emit_pop(self, RSCRATCH);
//      emit_ins(self, RiscVInstruction::load(OperandSize::S64, Register::T6, RSCRATCH, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr))));
//      emit_ins(self, RiscVInstruction::load(OperandSize::S64, RSCRATCH, REGISTER_MAP[0], X86IndirectAccess::Offset(8)));
//      emit_return(self);

        // Routine for prologue of emit_bpf_call()
        self.set_anchor(ANCHOR_BPF_CALL_PROLOGUE);
//      emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x81, 5, Register::SP, 8 * (SCRATCH_REGS + 1) as i64, None)); // alloca
//      emit_ins(self, RiscVInstruction::store(OperandSize::S64, RSCRATCH, Register::SP, X86IndirectAccess::OffsetIndexShift(0, Register::SP, 0))); // Save original RSCRATCH
//      emit_ins(self, RiscVInstruction::load(OperandSize::S64, Register::SP, RSCRATCH, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS + 1) as i32, Register::SP, 0))); // Load return address
        for (_, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).enumerate() {
//          emit_ins(self, RiscVInstruction::store(OperandSize::S64, *reg, Register::SP, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS - i + 1) as i32, Register::SP, 0)));
            emit_push(self, *reg); // Push SCRATCH_REG
        }
        // Push the caller's frame pointer. The code to restore it is emitted at the end of emit_bpf_call().
//      emit_ins(self, RiscVInstruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], Register::SP, X86IndirectAccess::OffsetIndexShift(8, Register::SP, 0)));
        emit_push(self, REGISTER_MAP[FRAME_PTR_REG]);
//      emit_ins(self, RiscVInstruction::xchg(OperandSize::S64, RSCRATCH, Register::SP, Some(X86IndirectAccess::OffsetIndexShift(0, Register::SP, 0)))); // Push return address and restore original RSCRATCH
        emit_push(self, RSCRATCH); // Save original RSCRATCH

        // Increase CallDepth
//      let call_depth_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::CallDepth));
//      emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, Register::T6, 1, Some(call_depth_access)));
//      emit_ins(self, RiscVInstruction::load(OperandSize::S64, Register::T6, REGISTER_MAP[FRAME_PTR_REG], call_depth_access));
        emit_load_offset(self, OperandSize::S64, Register::T6, RSCRATCH, slot_on_environment_stack(self, EnvironmentStackSlot::CallDepth));
        emit_add_imm(self, OperandSize::S32, RSCRATCH, 1); // assume max_call_depth < 2^32
        emit_store_offset(self, OperandSize::S64, Register::T6, RSCRATCH, slot_on_environment_stack(self, EnvironmentStackSlot::CallDepth));
        // TODO If CallDepth == self.config.max_call_depth, stop and return CallDepthExceeded
//      emit_ins(self, RiscVInstruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], self.config.max_call_depth as i64, None));
//      emit_ins(self, RiscVInstruction::conditional_jump_immediate(0x83, self.relative_to_anchor(ANCHOR_CALL_DEPTH_EXCEEDED)));

        // Setup the frame pointer for the new frame. What we do depends on whether we're using dynamic or fixed frames.
//      let frame_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfFramePtr));
        if self.config.dynamic_stack_frames {
//          // When dynamic frames are on, the next frame starts at the end of the current frame
//          let stack_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfStackPtr));
//          emit_ins(self, RiscVInstruction::load(OperandSize::S64, Register::T6, REGISTER_MAP[FRAME_PTR_REG], stack_ptr_access));
            emit_load_offset(self, OperandSize::S64, Register::T6, RSCRATCH, slot_on_environment_stack(self, EnvironmentStackSlot::BpfStackPtr));
//          emit_ins(self, RiscVInstruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], Register::T6, frame_ptr_access));
            emit_store_offset(self, OperandSize::S64, Register::T6, RSCRATCH, slot_on_environment_stack(self, EnvironmentStackSlot::BpfFramePtr));
        } else {
            //TODO
            panic!("static stack frames unimplemented");
            // With fixed frames we start the new frame at the next fixed offset
//          let stack_frame_size = self.config.stack_frame_size as i64 * if self.config.enable_stack_frame_gaps { 2 } else { 1 };
//          emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, Register::T6, stack_frame_size, Some(frame_ptr_access))); // frame_ptr += stack_frame_size;
//          emit_ins(self, RiscVInstruction::load(OperandSize::S64, Register::T6, REGISTER_MAP[FRAME_PTR_REG], frame_ptr_access)); // Load BpfFramePtr
        }
        emit_return(self);

        // Routine for emit_bpf_call(Value::Register())
        self.set_anchor(ANCHOR_BPF_CALL_REG);
        // Force alignment of RAX
//      emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i64 - 1), None)); // RAX &= !(INSN_SIZE - 1);
        emit_and_imm(self, OperandSize::S64, REGISTER_MAP[0], !(INSN_SIZE as i64 - 1)); // RAX &= !(INSN_SIZE - 1);

        // Upper bound check
        // if(RAX >= self.program_vm_addr + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
        let number_of_instructions = self.result.pc_section.len() - 1;
//      emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64 + (number_of_instructions * INSN_SIZE) as i64));
        emit_load_immediate(self, OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64 + (number_of_instructions * INSN_SIZE) as i64);
//      emit_ins(self, X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None));
//      emit_ins(self, X86Instruction::conditional_jump_immediate(0x83, self.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)));
        emit_ins(self, RiscVInstruction::bltu(REGISTER_MAP[FRAME_PTR_REG][1], REGISTER_MAP[0][1], 4 * 5));
        emit_ins(self, RiscVInstruction::bne(REGISTER_MAP[FRAME_PTR_REG][1], REGISTER_MAP[0][1], 4 * 2));
        emit_ins(self, RiscVInstruction::bltu(REGISTER_MAP[FRAME_PTR_REG][0], REGISTER_MAP[0][0], 4 * 3));
        emit_long_jump_to_anchor(self, Register::X0, ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT);

        // Lower bound check
        // if(RAX < self.program_vm_addr) throw CALL_OUTSIDE_TEXT_SEGMENT;
//      emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64));
        emit_load_immediate(self, OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64);
//      emit_ins(self, X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None));
//      emit_ins(self, X86Instruction::conditional_jump_immediate(0x82, self.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)));
        emit_ins(self, RiscVInstruction::bltu(REGISTER_MAP[0][1], REGISTER_MAP[FRAME_PTR_REG][1], 4 * 5));
        emit_ins(self, RiscVInstruction::bne(REGISTER_MAP[0][1], REGISTER_MAP[FRAME_PTR_REG][1], 4 * 2));
        emit_ins(self, RiscVInstruction::bleu(REGISTER_MAP[0][0], REGISTER_MAP[FRAME_PTR_REG][0], 4 * 3));
        emit_long_jump_to_anchor(self, Register::X0, ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT);

        // Calculate offset relative to instruction_addresses
//      emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x29, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None));
        emit_sub(self, OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0]); // RAX -= self.program_vm_addr;
        // Calculate the target_pc (dst / INSN_SIZE) to update the instruction_meter
//      let shift_amount = INSN_SIZE.trailing_zeros();
//      debug_assert_eq!(INSN_SIZE, 1 << shift_amount);
//      emit_ins(self, X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11));
//      emit_mov(self, OperandSize::S64, REGISTER_MAP[0], RSCRATCH);
//      emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xc1, 5, R11, shift_amount as i64, None));
//      emit_rsh_imm(self, OperandSize::S64, RSCRATCH, shift_amount as i64);
        // TODO Save BPF target pc for potential ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION
//      emit_ins(self, X86Instruction::store(OperandSize::S64, R11, RSP, X86IndirectAccess::OffsetIndexShift(-8, RSP, 0))); // RSP[-8] = R11;
        // Load host target_address from self.result.pc_section
//      debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
        emit_ins(self, RiscVInstruction::srli(REGISTER_MAP[0][0], REGISTER_MAP[0][0], 1)); // We need to shift once because the BPF instruction size is twice a RISCV32 pointer size
//      emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.result.pc_section.as_ptr() as i64));
        emit_load_symbol_address(self, REGISTER_MAP[FRAME_PTR_REG][0], "pc_offsets");
//      emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x01, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None));
        emit_ins(self, RiscVInstruction::add(REGISTER_MAP[0][0], REGISTER_MAP[FRAME_PTR_REG][0], REGISTER_MAP[0][0])); // r00 += pc_offsets;
//      emit_ins(self, X86Instruction::load(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], X86IndirectAccess::Offset(0)));
        emit_ins(self, RiscVInstruction::lw(REGISTER_MAP[0][0], REGISTER_MAP[0][0], 0)); // r00 = pc_offsets[RAX / 8];
        emit_load_symbol_address(self, REGISTER_MAP[0][1], "program_main"); // r01 = program_main;
        emit_ins(self, RiscVInstruction::add(REGISTER_MAP[0][0], REGISTER_MAP[0][1], REGISTER_MAP[0][0])); // r00 += r01;
        // Load the frame pointer again since we've clobbered REGISTER_MAP[FRAME_PTR_REG]
//      emit_ins(self, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfFramePtr))));
        let frame_ptr_offset = slot_on_environment_stack(self, EnvironmentStackSlot::BpfFramePtr);
        emit_load_offset(self, OperandSize::S64, Register::T6, REGISTER_MAP[FRAME_PTR_REG], frame_ptr_offset);
//      emit_ins(self, X86Instruction::return_near());
        emit_return(self);

        // Translates a host pc back to a BPF pc by linear search of the pc_section table
        self.set_anchor(ANCHOR_TRANSLATE_PC);
//      emit_push(self, REGISTER_MAP[0]); // Save REGISTER_MAP[0]
//      emit_load_immediate(self, OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64 - 8); // Loop index and pointer to look up
        self.set_anchor(ANCHOR_TRANSLATE_PC_LOOP); // Loop label
//      emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, REGISTER_MAP[0], 8, None)); // Increase index
//      emit_ins(self, RiscVInstruction::cmp(OperandSize::S64, RSCRATCH, REGISTER_MAP[0], Some(X86IndirectAccess::Offset(8)))); // Look up and compare against value at next index
//      emit_ins(self, RiscVInstruction::conditional_jump_immediate(0x86, self.relative_to_anchor(ANCHOR_TRANSLATE_PC_LOOP))); // Continue while *REGISTER_MAP[0] <= RSCRATCH
//      emit_ins(self, RiscVInstruction::mov(OperandSize::S64, REGISTER_MAP[0], RSCRATCH)); // RSCRATCH = REGISTER_MAP[0];
//      emit_load_immediate(self, OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64); // REGISTER_MAP[0] = self.result.pc_section;
//      emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x29, REGISTER_MAP[0], RSCRATCH, 0, None)); // RSCRATCH -= REGISTER_MAP[0];
//      emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0xc1, 5, RSCRATCH, 3, None)); // RSCRATCH >>= 3;
//      emit_pop(self, REGISTER_MAP[0]); // Restore REGISTER_MAP[0]
//      emit_return(self);

        self.set_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION);
//      emit_ins(self, RiscVInstruction::alu(OperandSize::S64, 0x81, 0, Register::SP, 8, None));
//      emit_pop(self, RSCRATCH); // Put callers PC in RSCRATCH
//      emit_call(self, self.relative_to_anchor(ANCHOR_TRANSLATE_PC));
//      emit_jump_to_anchor(self, Register::X0, ANCHOR_EXCEPTION_AT);

        // Translates a vm memory address to a host memory address
        for (access_type, len) in &[
            (AccessType::Load, 1i32),
            (AccessType::Load, 2i32),
            (AccessType::Load, 4i32),
            (AccessType::Load, 8i32),
            (AccessType::Store, 1i32),
            (AccessType::Store, 2i32),
            (AccessType::Store, 4i32),
            (AccessType::Store, 8i32),
        ] {
            let target_offset = len.trailing_zeros() as usize + 4 * (*access_type as usize);
            self.set_anchor(ANCHOR_TRANSLATE_MEMORY_ADDRESS + target_offset);

            /*
             * The Solana memory model is as follows:
             *   program data is loaded at 0x100000000
             *   the stack starts at 0x200000000 and has a maximum size of 64 * 4 KiB
             *   the heap starts at 0x300000000 and is 32 KiB
             *   input data is loaded at 0x400000000
             *
             * More details are at https://docs.solana.com/developing/on-chain-programs/overview
             */
            emit_return(self);
        }
        Ok(())
    }

    fn add_to_pc_section(&mut self, offset : usize) {
        let text_section_base = self.result.text_section.as_ptr();
        self.result.pc_section[self.pc] = unsafe { text_section_base.add(offset) } as usize;
        self.pc_offsets[self.pc] = offset as u32;
    }

    fn set_anchor(&mut self, anchor: usize) {
        self.anchors[anchor] = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) };
        self.anchor_offsets[anchor] = self.offset_in_text_section;
    }

    #[inline]
    fn relative_to_anchor(&self, anchor: usize) -> i32 {
        let instruction_start = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) };
        let destination = self.anchors[anchor];
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_start) } as i32) // Relative jump
    }

    #[inline]
    fn relative_to_target_pc(&mut self, target_pc: usize) -> Option<i32> {
        let instruction_start = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) };
        let destination = if self.result.pc_section[target_pc] != 0 {
            // Backward jump
            self.result.pc_section[target_pc] as *const u8
        } else {
            // Forward jump, needs relocation
            self.text_section_jumps.push(Jump { location: instruction_start, target_pc });
            return None;
        };
        debug_assert!(!destination.is_null());
        Some(unsafe { destination.offset_from(instruction_start) } as i32)
    }

    fn resolve_jumps(&mut self) {
        // Relocate forward jumps
        for jump in &self.text_section_jumps {
            let destination = self.result.pc_section[jump.target_pc] as *const u8;
            let offset = unsafe { destination.offset_from(jump.location) } as i32; // Relative jump
            let (upper, lower) = make_split_immediate(offset);
            let original_instr2 = unsafe { ptr::read_unaligned((jump.location as *mut i32).add(1)) };
            let instr1 = RiscVInstruction::auipc(RSCRATCH2[0], upper).encode() as i32;
            let instr2 = (lower << 20) | (original_instr2 & ((1 << 20) - 1));
            unsafe {
                ptr::write_unaligned(jump.location as *mut i32, instr1);
                ptr::write_unaligned((jump.location as *mut i32).add(1), instr2);
            }
        }
        // There is no `VerifierError::JumpToMiddleOfLDDW` for `call imm` so patch it here
        let call_unsupported_instruction = self.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
        let callx_unsupported_instruction = self.anchors[ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION] as usize;
        for offset in self.result.pc_section.iter_mut() {
            if *offset == call_unsupported_instruction {
                *offset = callx_unsupported_instruction;
            }
        }
    }
}

#[cfg(all(test, target_arch = "x86_64", not(target_os = "windows")))]
mod tests {
    use super::*;
    use crate::{syscalls, vm::{SyscallRegistry, SyscallObject, TestInstructionMeter}, elf::register_bpf_function, user_error::UserError};
    use std::collections::BTreeMap;
    use byteorder::{LittleEndian, ByteOrder};

    fn create_mockup_executable(program: &[u8]) -> Executable::<UserError, TestInstructionMeter> {
        let config = Config {
            noop_instruction_rate: 0,
            ..Config::default()
        };
        let mut syscall_registry = SyscallRegistry::default();
        syscall_registry
            .register_syscall_by_hash(
                0xFFFFFFFF,
                syscalls::BpfGatherBytes::init::<syscalls::BpfSyscallContext, UserError>,
                syscalls::BpfGatherBytes::call,
            )
            .unwrap();
        let mut bpf_functions = BTreeMap::new();
        register_bpf_function(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            0,
            "entrypoint",
        )
        .unwrap();
        bpf_functions.insert(0xFFFFFFFF, (8, "foo".to_string()));
        Executable::<UserError, TestInstructionMeter>::from_text_bytes(
            program,
            config,
            syscall_registry,
            bpf_functions,
        )
        .unwrap()
    }

    #[test]
    fn test_code_length_estimate() {
        const INSTRUCTION_COUNT: usize = 256;
        let mut prog = [0; ebpf::INSN_SIZE * INSTRUCTION_COUNT];

        let empty_program_machine_code_length = {
            prog[0] = ebpf::EXIT;
            let mut executable = create_mockup_executable(&[]);
            Executable::<UserError, TestInstructionMeter>::jit_compile(&mut executable).unwrap();
            executable.get_compiled_program().unwrap().machine_code_length()
        };
        assert!(empty_program_machine_code_length <= MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH);

        for opcode in 0..255 {
            for pc in 0..INSTRUCTION_COUNT {
                prog[pc * ebpf::INSN_SIZE] = opcode;
                prog[pc * ebpf::INSN_SIZE + 1] = 0x88;
                prog[pc * ebpf::INSN_SIZE + 2] = 0xFF;
                prog[pc * ebpf::INSN_SIZE + 3] = 0xFF;
                LittleEndian::write_u32(&mut prog[pc * ebpf::INSN_SIZE + 4..], match opcode {
                    0x8D => 8,
                    0xD4 | 0xDC => 16,
                    _ => 0xFFFFFFFF,
                });
            }
            let mut executable = create_mockup_executable(&prog);
            let result = Executable::<UserError, TestInstructionMeter>::jit_compile(&mut executable);
            if result.is_err() {
                assert!(matches!(result.unwrap_err(), EbpfError::UnsupportedInstruction(_)));
                continue;
            }
            let machine_code_length = executable.get_compiled_program().unwrap().machine_code_length() - empty_program_machine_code_length;
            let instruction_count = if opcode == 0x18 { INSTRUCTION_COUNT / 2 } else { INSTRUCTION_COUNT };
            let machine_code_length_per_instruction = (machine_code_length as f64 / instruction_count as f64 + 0.5) as usize;
            assert!(machine_code_length_per_instruction <= MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION);
        }
    }
}
