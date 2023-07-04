extern crate rvsim;

use solana_rbpf::{
    assembler::assemble,
    compiler::{Compiler, RiscVRelocation, REGISTER_MAP},
    ebpf::FRAME_PTR_REG,
    riscv::{Register, RiscVInstruction},
    user_error::UserError,
    vm::{Config, SyscallRegistry, TestInstructionMeter},
};

struct FuzzerMemory<'a> {
    memory: Vec<u8>,
    preamble: Vec<u8>,
    body: &'a mut [u8],
}

impl<'a> FuzzerMemory<'a> {
    const PROGRAM_BASE: u32 = 0x1000_0000;

    fn new(preamble: Vec<RiscVInstruction>, body: &'a mut [u8]) -> Self {
        let preamble_bytes = preamble.iter().flat_map(|i| i.encode().to_le_bytes()).collect();
        Self {
            memory: vec![0; Self::PROGRAM_BASE as usize],
            preamble: preamble_bytes,
            body,
        }
    }
}

impl<'a> rvsim::Memory for FuzzerMemory<'a> {
    fn access<T: Copy>(&mut self, addr: u32, access: rvsim::MemoryAccess<T>) -> bool {
        let body_base = Self::PROGRAM_BASE + (self.preamble.len() as u32);
        if addr >= body_base {
            rvsim::Memory::access(&mut self.body[..], addr - body_base, access)
        } else if addr >= Self::PROGRAM_BASE {
            rvsim::Memory::access(&mut self.preamble[..], addr - Self::PROGRAM_BASE, access)
        } else {
            rvsim::Memory::access(&mut self.memory[..], addr, access)
        }
    }
}

pub fn run_bpf(bpf: String) -> Vec<u64> {
    let config = Config {
        encrypt_environment_registers: false,
        noop_instruction_rate: 0,
        ..Config::default()
    };
    let syscall_registry = SyscallRegistry::default();
    let bpf_executable = assemble::<UserError, TestInstructionMeter>(
        &bpf[..],
        config,
        syscall_registry,
    ).unwrap();

    let (_, text_bytes) = bpf_executable.get_text_bytes();
    let mut compiler = Compiler::new::<UserError>(text_bytes, &config).unwrap();
    compiler.restore_registers = false;

    compiler.compile(&bpf_executable).unwrap();

    let riscv_bytecode = compiler.result.text_section;

    let ebreak_bytes = RiscVInstruction::ebreak().encode().to_le_bytes();
    for relocation in compiler.relocations {
        let offset = match relocation {
            RiscVRelocation::Call{offset, ..} => offset,
            RiscVRelocation::Hi20{offset, ..} => offset,
            RiscVRelocation::Lo12I{offset, ..} => offset,
        };
        riscv_bytecode[offset .. offset + 4].copy_from_slice(&ebreak_bytes);
    }

    let preamble = vec![
        // set up stack pointer
        RiscVInstruction::auipc(Register::SP, 0),
        // set GP = 0 so we know if execution halted partway
        RiscVInstruction::mv(Register::X0, Register::GP),
        // jump to the body
        RiscVInstruction::jal(Register::RA, 12),
        // set GP = 1 to indicate that we exited successfully
        RiscVInstruction::addi(Register::X0, Register::GP, 1),
        // exit
        RiscVInstruction::ebreak(),
    ];

    let mut mem = FuzzerMemory::new(preamble, riscv_bytecode);
    let mut clock = rvsim::SimpleClock::new();
    let mut state = rvsim::CpuState::new(FuzzerMemory::PROGRAM_BASE);
    let mut interp = rvsim::Interp::new(&mut state, &mut mem, &mut clock);
    let (err, op) = interp.run();
    let pc = state.pc - FuzzerMemory::PROGRAM_BASE - (mem.preamble.len() as u32);

    // check that we exited correctly
    assert_eq!(err, rvsim::CpuError::Ebreak, "RISC-V program exited incorrectly");
    assert_eq!(op, Some(rvsim::Op::Ebreak), "RISC-V program exited incorrectly");
    assert_eq!(state.x[Register::GP as usize], 1, "RISC-V program exited prematurely at position {pc}");

    assert_eq!(FRAME_PTR_REG, 10);
    REGISTER_MAP
        .iter()
        .take(10)
        .map(|[r1, r2]|
             (state.x[*r1 as usize] as u64) + ((state.x[*r2 as usize] as u64) << 32))
        .collect()
}
