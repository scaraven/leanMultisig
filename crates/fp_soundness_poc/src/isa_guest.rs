//! A hand-written leanISA program: a benign `fib(N) == public_input[0]` verifier.
//!
//! It is *semantically* the same fibonacci check as `crate::guest`, but written directly
//! in leanISA instead of the zkDSL. The difference is deliberate and is the whole point of
//! the PoC: the zkDSL compiler happens to emit `write_call_frame` dereferences that pin the
//! saved frame pointer and range-check the callee base, so the compiled bytecode
//! *accidentally* constrains `fp`. Nothing in the AIR requires that. This hand-written
//! version omits the incidental pin — the one jump that reloads `fp` takes its new value
//! from a `hint_witness` cell the AIR never constrains — exposing the raw frame-pointer
//! under-constraint (audit F-2).
//!
//! Honest control flow (frame pointer `F0 = 10` throughout):
//!   1. compute `fib(N)` into `m[fp+RES]`;
//!   2. `hint_witness` writes the honest fp (`F0`) into `m[fp+H]`;
//!   3. `JUMP` reloads `fp <- m[fp+H]` (a no-op honestly) — the hijack point;
//!   4. read the public claim `m[0]` into `m[fp+CLAIM]` (deref through a zero pointer);
//!   5. assert `m[fp+RES] == m[fp+CLAIM]`;
//!   6. halt.
//! Honest semantics: the proof exists iff `public_input[0] == fib(N)`.
//!
//! The malicious prover (see `crate::forge::forge_isa`) instead loads an *out-of-range*
//! `fp = p - RES` at step 3, so at step 5 the result read `m[fp+RES]` wraps modulo `p` onto
//! `m[0]` — the public claim itself — making the assert `m[0] == m[0]` pass for any claim.

use backend::*;
use lean_vm::*;
use std::collections::BTreeMap;

/// Fibonacci index and its true value (fib: 0,1,1,2,3,5,8,13,21,34,55 → fib(10) = 55).
pub const N: usize = 10;
pub const FIB_N: u32 = 55;

/// Honest initial frame pointer: `next_multiple_of(PUBLIC_INPUT_LEN + preamble, DIMENSION)`
/// with an empty preamble = `next_multiple_of(8, 5) = 10`.
pub const F0: usize = 10;

// Frame-relative offsets (small, so honest `F0 + offset` stays in range and the malicious
// `(p - RES) + offset` wraps back into range).
const BUFF: usize = 2; // fib buffer base: buff[i] at fp + BUFF + i
pub const RES: usize = BUFF + N; // fib(N) = buff[N] at fp + RES  (= 12)
pub const PTR: usize = 20; // holds the constant 0, used as the deref pointer to reach m[0]
pub const CLAIM: usize = 21; // holds the claim read from m[0]
pub const H: usize = 25; // holds the (unconstrained) reloaded frame pointer

// Padding so the execution table clears MIN_LOG_N_ROWS_PER_TABLE (256 rows).
const FILL_BASE: usize = 100;
const FILL_COUNT: usize = 260;

/// pc (= cycle, the program is straight-line up to here) of the hijack jump:
/// 2 fib seeds + (N-1) fib adds + FILL_COUNT fillers.
pub const JUMP_PC: usize = 2 + (N - 1) + FILL_COUNT;

const HINT_NAME: &str = "fp_hint";

fn set_const(off: usize, v: u32) -> Instruction {
    // res = arg_a + arg_c  ⇒  v = 0 + m[fp+off]  ⇒  m[fp+off] := v
    Instruction::Computation {
        operation: Operation::Add,
        arg_a: MemOrConstant::Constant(F::ZERO),
        arg_c: MemOrFpOrConstant::MemoryAfterFp { offset: off },
        res: MemOrConstant::Constant(F::from_u32(v)),
    }
}

fn add(dst: usize, a: usize, b: usize) -> Instruction {
    // m[fp+dst] := m[fp+a] + m[fp+b]
    Instruction::Computation {
        operation: Operation::Add,
        arg_a: MemOrConstant::MemoryAfterFp { offset: a },
        arg_c: MemOrFpOrConstant::MemoryAfterFp { offset: b },
        res: MemOrConstant::MemoryAfterFp { offset: dst },
    }
}

fn assert_eq(lhs: usize, rhs: usize) -> Instruction {
    // res = arg_a + arg_c  with all three known  ⇒  checks m[fp+lhs] == m[fp+rhs] + 0
    Instruction::Computation {
        operation: Operation::Add,
        arg_a: MemOrConstant::MemoryAfterFp { offset: rhs },
        arg_c: MemOrFpOrConstant::Constant(F::ZERO),
        res: MemOrConstant::MemoryAfterFp { offset: lhs },
    }
}

fn entry(instruction: Instruction) -> CodeEntry {
    CodeEntry {
        hints: Box::new([]),
        instruction,
    }
}

fn self_jump(pc: usize) -> CodeEntry {
    entry(Instruction::Jump {
        condition: MemOrConstant::one(),
        label: Label::custom(format!("pc{pc}")),
        dest: MemOrConstant::Constant(F::from_usize(pc)),
        updated_fp: MemOrFpOrConstant::FpRelative { offset: 0 },
    })
}

/// Build the hand-written bytecode plus the honest hint value (`F0`).
pub fn build_bytecode() -> Bytecode {
    let mut code: Vec<CodeEntry> = Vec::new();

    // --- fib(N) into m[fp+BUFF .. fp+RES] ---
    code.push(entry(set_const(BUFF, 0))); // buff[0] = 0
    code.push(entry(set_const(BUFF + 1, 1))); // buff[1] = 1
    for i in 2..=N {
        code.push(entry(add(BUFF + i, BUFF + i - 1, BUFF + i - 2))); // buff[i] = buff[i-1]+buff[i-2]
    }

    // --- padding cycles (benign; keeps the execution table above the min height) ---
    for k in 0..FILL_COUNT {
        code.push(entry(set_const(FILL_BASE + k, 0)));
    }

    // --- the hijack jump: reload fp from the hint cell m[fp+H], continue at pc+1 ---
    let jump_pc = code.len();
    let mut jump = entry(Instruction::Jump {
        condition: MemOrConstant::one(),
        label: Label::custom("reload_fp"),
        dest: MemOrConstant::Constant(F::from_usize(jump_pc + 1)),
        updated_fp: MemOrFpOrConstant::MemoryAfterFp { offset: H },
    });
    jump.hints = Box::new([Hint::HintWitness {
        slot: 0,
        destination: HintWitnessDestination::Inline { offset: H },
    }]);
    code.push(jump);

    // --- post-jump: read the public claim and assert it equals the fib result ---
    code.push(entry(set_const(PTR, 0))); // m[fp+PTR] = 0  (pointer to m[0])
    code.push(entry(Instruction::Deref {
        shift_0: PTR,
        shift_1: 0,
        res: MemOrFpOrConstant::MemoryAfterFp { offset: CLAIM },
    })); // m[fp+CLAIM] = m[m[fp+PTR]+0] = m[0] = public claim
    code.push(entry(assert_eq(RES, CLAIM))); // assert fib(N) == claim

    // --- reach ending_pc to halt ---
    let unpadded_size = code.len() + 1; // + the final jump-to-halt
    let padded_len = (unpadded_size + 1).next_power_of_two();
    let ending_pc = padded_len - 1;
    // updated_fp = 0 so the halt row's frame pointer matches the execution table's
    // self-jump padding rows (which carry fp = 0); otherwise the transition constraint
    // between the last real row and the first padding row fails.
    code.push(entry(Instruction::Jump {
        condition: MemOrConstant::one(),
        label: Label::custom("halt"),
        dest: MemOrConstant::Constant(F::from_usize(ending_pc)),
        updated_fp: MemOrFpOrConstant::Constant(F::ZERO),
    }));
    while code.len() < padded_len {
        let pc = code.len();
        code.push(self_jump(pc));
    }

    let mut hint_name_to_index = BTreeMap::new();
    hint_name_to_index.insert(HINT_NAME.to_string(), 0usize);

    let loc = SourceLocation {
        file_id: 0,
        line_number: 0,
    };
    let debug_info = BytecodeDebugInfo {
        pc_to_location: vec![loc; code.len()],
        ..Default::default()
    };

    Bytecode::new(code, unpadded_size, 400, hint_name_to_index, debug_info)
}

/// Honest witness: `hint_witness("fp_hint")` supplies the honest frame pointer `F0`, so the
/// hijack jump is a no-op and the assert reads the genuine fib result.
pub fn honest_witness(bytecode: &Bytecode) -> ExecutionWitness {
    let mut hints = Hints::default();
    hints.insert(
        bytecode,
        // leak a 'static str for the &'static bound
        Box::leak(HINT_NAME.to_string().into_boxed_str()),
        arena_vec![ArenaVec::from_slice(&[F::from_usize(F0)])],
    );
    ExecutionWitness {
        preamble_memory_len: 0,
        hints,
        ..Default::default()
    }
}
