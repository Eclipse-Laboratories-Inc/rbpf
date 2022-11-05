#![allow(clippy::integer_arithmetic)]
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

// System V AMD64 ABI
// Works on: Linux, macOS, BSD and Solaris but not on Windows
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

pub const OP_IMM : u8 = 0b0010011;
pub const OP_LUI : u8 = 0b0110111;
pub const OP_OP  : u8 = 0b0110011;

#[derive(Copy, Clone)]
pub struct RiscVInstruction {
    format: InstructionFormat,
    opcode: u8,
    funct3 : u8,
    funct7 : u8,
    source1: Register,
    source2: Register,
    destination: Register,
    immediate: i32,
}

#[inline]
fn pick_bits(num: i32, most_sig : u8, least_sig : u8, offset : u8) -> u32 {
    return (((num >> least_sig) | ((1 << (most_sig - least_sig + 1)) - 1)) << offset) as u32;
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
                if self.immediate >= 0 {
                    assert!(self.immediate | ((1 << 11) - 1) == ((1 << 11) - 1));
                } else {
                    assert!(self.immediate | ((1 << 11) - 1) == -1);
                }
            }
            InstructionFormat::S => {
                assert!(self.funct7 == 0);
                assert!(self.destination == Register::X0);
                if self.immediate >= 0 {
                    assert!(self.immediate | ((1 << 11) - 1) == ((1 << 11) - 1));
                } else {
                    assert!(self.immediate | ((1 << 11) - 1) == -1);
                }
            }
            InstructionFormat::B => {
                assert!(self.funct7 == 0);
                assert!(self.destination == Register::X0);
                assert!(self.immediate % 2 == 0);
                if self.immediate >= 0 {
                    assert!(self.immediate | ((1 << 12) - 1) == ((1 << 12) - 1));
                } else {
                    assert!(self.immediate | ((1 << 12) - 1) == -1);
                }
            }
            InstructionFormat::U => {
                assert!(self.funct3 == 0);
                assert!(self.funct7 == 0);
                assert!(self.source1 == Register::X0);
                assert!(self.source2 == Register::X0);
                assert!(self.immediate % (1 << 12) == 0);
            }
            InstructionFormat::J => {
                assert!(self.funct3 == 0);
                assert!(self.funct7 == 0);
                assert!(self.source1 == Register::X0);
                assert!(self.source2 == Register::X0);
                assert!(self.immediate % 2 == 0);
                if self.immediate >= 0 {
                    assert!(self.immediate | ((1 << 20) - 1) == ((1 << 20) - 1));
                } else {
                    assert!(self.immediate | ((1 << 20) - 1) == -1);
                }
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
                | pick_bits(self.immediate, 1, 4, 8) | pick_bits(self.immediate, 11, 11, 7),
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

    /// Add a 12-bit immediate and source, outputting to destination
    #[inline]
    pub const fn addi(source: Register, destination: Register, immediate: i32) -> Self {
        Self {
            format: InstructionFormat::I,
            opcode: OP_IMM,
            funct3: 0b000,
            source1: source,
            destination,
            immediate,
            ..Self::DEFAULT
        }
    }

    /// Load immediate (whose last 12 bits are zero) into destination
    #[inline]
    pub const fn lui(destination: Register, immediate: i32) -> Self {
        Self {
            format: InstructionFormat::U,
            opcode: OP_LUI,
            destination,
            immediate,
            ..Self::DEFAULT
        }
    }

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

    /// Add source1 and source2, outputting to destination
    #[inline]
    pub const fn add(source1: Register, source2: Register, destination: Register) -> Self {
        Self {
            format: InstructionFormat::R,
            opcode: OP_OP,
            funct3: 0b000,
            funct7: 0b0000000,
            source1,
            source2,
            destination,
            ..Self::DEFAULT
        }
    }

    /// Subtract source2 from source1, outputting to destination
    #[inline]
    pub const fn sub(source1: Register, source2: Register, destination: Register) -> Self {
        Self {
            format: InstructionFormat::R,
            opcode: OP_OP,
            funct3: 0b000,
            funct7: 0b0100000,
            source1,
            source2,
            destination,
            ..Self::DEFAULT
        }
    }
}
