#![allow(clippy::integer_arithmetic)]
// Copyright 2022 Eclipse Labs
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>.
// This file may not be copied, modified, or distributed except according to those terms.

//! This module includes functions to output RISC-V bytecode

use crate::compiler::{emit, Compiler};

#[derive(Copy, Clone, PartialEq)]
pub enum Register {
    X0  =  0,
    RA  =  1,
    SP  =  2,
    GP  =  3,
    TP  =  4,
    T0  =  5,
    T1  =  6,
    T2  =  7,
    S0  =  8,
    S1  =  9,
    A0  = 10,
    A1  = 11,
    A2  = 12,
    A3  = 13,
    A4  = 14,
    A5  = 15,
    A6  = 16,
    A7  = 17,
    S2  = 18,
    S3  = 19,
    S4  = 20,
    S5  = 21,
    S6  = 22,
    S7  = 23,
    S8  = 24,
    S9  = 25,
    S10 = 26,
    S11 = 27,
    T3  = 28,
    T4  = 29,
    T5  = 30,
    T6  = 31,
}

pub const ARGUMENT_REGISTERS: [Register; 8] = [
    Register::A0,
    Register::A1,
    Register::A2,
    Register::A3,
    Register::A4,
    Register::A5,
    Register::A6,
    Register::A7
];
pub const CALLER_SAVED_REGISTERS: [Register; 16] = [
    Register::RA,
    Register::T0,
    Register::T1,
    Register::T2,
    Register::A0,
    Register::A1,
    Register::A2,
    Register::A3,
    Register::A4,
    Register::A5,
    Register::A6,
    Register::A7,
    Register::T3,
    Register::T4,
    Register::T5,
    Register::T6
];
pub const CALLEE_SAVED_REGISTERS: [Register; 13] = [
    Register::SP,
    Register::S0,
    Register::S1,
    Register::S2,
    Register::S3,
    Register::S4,
    Register::S5,
    Register::S6,
    Register::S7,
    Register::S8,
    Register::S9,
    Register::S10,
    Register::S11
];

#[derive(Copy, Clone)]
pub enum InstructionFormat {
    R = 0,
    I = 1,
    S = 2,
    B = 3,
    U = 4,
    J = 5,
}

#[derive(Copy, Clone)]
pub struct RiscVInstruction {
    pub format: InstructionFormat,
    pub opcode: u8,
    pub funct3 : u8,
    pub funct7 : u8,
    pub source1: Register,
    pub source2: Register,
    pub destination: Register,
    pub immediate: i32,
}

#[inline]
fn pick_bits(num: i32, most_sig : u8, least_sig : u8, offset : u8) -> u32 {
    return (((num as u32) >> least_sig) & ((1 << (most_sig - least_sig + 1)) - 1)) << offset;
}

macro_rules! define_instruction {
    ($name:ident, R, $opcode:expr, $funct3:expr, $funct7:expr) => {
        #[inline]
        pub const fn $name(source1: Register, source2: Register, destination: Register) -> Self {
            Self {
                format: InstructionFormat::R,
                opcode: $opcode,
                funct3: $funct3,
                funct7: $funct7,
                source1,
                source2,
                destination,
                ..Self::DEFAULT
            }
        }
    };
    ($name:ident, I, $opcode:expr, $funct3:expr) => {
        #[inline]
        pub const fn $name(source: Register, destination: Register, immediate: i32) -> Self {
            Self {
                format: InstructionFormat::I,
                opcode: $opcode,
                funct3: $funct3,
                source1: source,
                destination,
                immediate,
                ..Self::DEFAULT
            }
        }
    };
    ($name:ident, S, $opcode:expr, $funct3:expr) => { define_instruction_SB!($name, S, $opcode, $funct3); };
    ($name:ident, B, $opcode:expr, $funct3:expr) => { define_instruction_SB!($name, B, $opcode, $funct3); };
    ($name:ident, U, $opcode:expr) => { define_instruction_UJ!($name, U, $opcode); };
    ($name:ident, J, $opcode:expr) => { define_instruction_UJ!($name, J, $opcode); };
}

#[allow(unused_macros)]
macro_rules! define_instruction_SB {
    ($name:ident, $type:ident, $opcode:expr, $funct3:expr) => {
        #[inline]
        pub const fn $name(source1: Register, source2: Register, immediate: i32) -> Self {
            Self {
                format: InstructionFormat::$type,
                opcode: $opcode,
                funct3: $funct3,
                source1,
                source2,
                immediate,
                ..Self::DEFAULT
            }
        }
    }
}

#[allow(unused_macros)]
macro_rules! define_instruction_UJ {
    ($name:ident, $type:ident, $opcode:expr) => {
        #[inline]
        pub const fn $name(destination: Register, immediate: i32) -> Self {
            Self {
                format: InstructionFormat::$type,
                opcode: $opcode,
                destination,
                immediate,
                ..Self::DEFAULT
            }
        }
    }
}

impl RiscVInstruction {
    pub const DEFAULT: RiscVInstruction = RiscVInstruction {
        format: InstructionFormat::R,
        opcode: 0,
        funct3: 0,
        funct7: 0,
        source1: Register::X0,
        source2: Register::X0,
        destination: Register::X0,
        immediate: 0,
    };

    #[inline]
    pub fn emit(&self, compiler: &mut Compiler) {
        emit::<u32>(compiler, self.encode());
    }

    #[inline]
    pub fn encode(&self) -> u32 {
        assert!(self.opcode & !0b1111111 == 0);
        assert!(self.funct3 & !0b111 == 0);
        assert!(self.funct7 & !0b1111111 == 0);
        match self.format {
            InstructionFormat::R => {
                assert!(self.immediate == 0);
            }
            InstructionFormat::I => {
                assert!(self.funct7 == 0);
                assert!(self.source2 == Register::X0);
//              if self.immediate >= 0 {
//                  assert!(self.immediate | ((1 << 11) - 1) == ((1 << 11) - 1));
//              } else {
//                  assert!(self.immediate | ((1 << 11) - 1) == -1);
//              }
            }
            InstructionFormat::S => {
                assert!(self.funct7 == 0);
                assert!(self.destination == Register::X0);
//              if self.immediate >= 0 {
//                  assert!(self.immediate | ((1 << 11) - 1) == ((1 << 11) - 1));
//              } else {
//                  assert!(self.immediate | ((1 << 11) - 1) == -1);
//              }
            }
            InstructionFormat::B => {
                assert!(self.funct7 == 0);
                assert!(self.destination == Register::X0);
//              assert!(self.immediate % 2 == 0);
//              if self.immediate >= 0 {
//                  assert!(self.immediate | ((1 << 12) - 1) == ((1 << 12) - 1));
//              } else {
//                  assert!(self.immediate | ((1 << 12) - 1) == -1);
//              }
            }
            InstructionFormat::U => {
                assert!(self.funct3 == 0);
                assert!(self.funct7 == 0);
                assert!(self.source1 == Register::X0);
                assert!(self.source2 == Register::X0);
//              assert!(self.immediate % (1 << 12) == 0);
            }
            InstructionFormat::J => {
                assert!(self.funct3 == 0);
                assert!(self.funct7 == 0);
                assert!(self.source1 == Register::X0);
                assert!(self.source2 == Register::X0);
//              assert!(self.immediate % 2 == 0);
//              if self.immediate >= 0 {
//                  assert!(self.immediate | ((1 << 20) - 1) == ((1 << 20) - 1));
//              } else {
//                  assert!(self.immediate | ((1 << 20) - 1) == -1);
//              }
            }
        }
        let immediate_encoded : u32 = match self.format {
            InstructionFormat::R => 0,
            InstructionFormat::I =>
                pick_bits(self.immediate, 11, 0, 20),
            InstructionFormat::S =>
                pick_bits(self.immediate, 11, 5, 25) | pick_bits(self.immediate, 4, 0, 7),
            InstructionFormat::B =>
                pick_bits(self.immediate, 12, 12, 31) | pick_bits(self.immediate, 10, 5, 25)
                | pick_bits(self.immediate, 4, 1, 8) | pick_bits(self.immediate, 11, 11, 7),
            InstructionFormat::U =>
                pick_bits(self.immediate, 31, 12, 12),
            InstructionFormat::J =>
                pick_bits(self.immediate, 20, 20, 31) | pick_bits(self.immediate, 10, 1, 21)
                | pick_bits(self.immediate, 11, 11, 20) | pick_bits(self.immediate, 19, 12, 12),
        };
        return ((self.funct7 as u32) << 25)
             | ((self.source2 as u32) << 20)
             | ((self.source1 as u32) << 15)
             | ((self.funct3 as u32) << 12)
             | ((self.destination as u32) << 7)
             | (self.opcode as u32)
             | immediate_encoded;
    }

    define_instruction!(add,    R, 0b0110011, 0b000, 0b0000000);
    define_instruction!(addi,   I, 0b0010011, 0b000);
    define_instruction!(and,    R, 0b0110011, 0b111, 0b0000000);
    define_instruction!(andi,   I, 0b0010011, 0b111);
    define_instruction!(auipc,  U, 0b0010111);
    define_instruction!(beq,    B, 0b1100011, 0b000);
    define_instruction!(bge,    B, 0b1100011, 0b101);
    define_instruction!(bgeu,   B, 0b1100011, 0b111);
    define_instruction!(blt,    B, 0b1100011, 0b100);
    define_instruction!(bltu,   B, 0b1100011, 0b110);
    define_instruction!(bne,    B, 0b1100011, 0b001);
    define_instruction!(div,    R, 0b0110011, 0b100, 0b0000001);
    define_instruction!(divu,   R, 0b0110011, 0b101, 0b0000001);
    define_instruction!(jal,    J, 0b1101111);
    define_instruction!(jalr,   I, 0b1100111, 0b000);
    define_instruction!(lb,     I, 0b0000011, 0b000);
    define_instruction!(lbu,    I, 0b0000011, 0b100);
    define_instruction!(lh,     I, 0b0000011, 0b001);
    define_instruction!(lhu,    I, 0b0000011, 0b101);
    define_instruction!(lui,    U, 0b0110111);
    define_instruction!(lw,     I, 0b0000011, 0b010);
    define_instruction!(mul,    R, 0b0110011, 0b000, 0b0000001);
    define_instruction!(mulh,   R, 0b0110011, 0b001, 0b0000001);
    define_instruction!(mulhsu, R, 0b0110011, 0b010, 0b0000001);
    define_instruction!(mulhu,  R, 0b0110011, 0b011, 0b0000001);
    define_instruction!(or,     R, 0b0110011, 0b110, 0b0000000);
    define_instruction!(ori,    I, 0b0010011, 0b110);
    define_instruction!(rem,    R, 0b0110011, 0b110, 0b0000001);
    define_instruction!(remu,   R, 0b0110011, 0b111, 0b0000001);
    define_instruction!(sb,     S, 0b0100011, 0b000);
    define_instruction!(sh,     S, 0b0100011, 0b001);
    define_instruction!(sll,    R, 0b0110011, 0b001, 0b0000000);
    define_instruction!(slt,    R, 0b0110011, 0b010, 0b0000000);
    define_instruction!(slti,   I, 0b0010011, 0b010);
    define_instruction!(sltiu,  I, 0b0010011, 0b011);
    define_instruction!(sltu,   R, 0b0110011, 0b011, 0b0000000);
    define_instruction!(sra,    R, 0b0110011, 0b101, 0b0100000);
    define_instruction!(srl,    R, 0b0110011, 0b101, 0b0000000);
    define_instruction!(sub,    R, 0b0110011, 0b000, 0b0100000);
    define_instruction!(sw,     S, 0b0100011, 0b010);
    define_instruction!(xor,    R, 0b0110011, 0b100, 0b0000000);
    define_instruction!(xori,   I, 0b0010011, 0b100);

    // Exceptional instructions

    #[inline]
    pub const fn ecall() -> Self {
        Self {
            format: InstructionFormat::I,
            opcode: 0b1110011,
            ..Self::DEFAULT
        }
    }

    // Pseudo-instructions

    /// Move source to destination
    #[inline]
    pub const fn mv(source: Register, destination: Register) -> Self {
        Self::addi(source, destination, 0)
    }

    /// No-op
    #[inline]
    pub const fn nop() -> Self {
        Self::addi(Register::X0, Register::X0, 0)
    }

    #[inline]
    pub const fn not(source: Register, destination: Register) -> Self {
        Self::xori(source, destination, -1)
    }
}
