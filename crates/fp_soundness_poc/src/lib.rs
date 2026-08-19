//! Proof-of-concept for the leanVM frame-pointer under-constraint (audit finding F-2).
//!
//! The deployed execution AIR never constrains the frame pointer `fp` to lie in the
//! memory range, never pins it at a boundary, and never range-checks its updates. `fp`
//! is therefore a free field element. This crate turns that gap into a concrete forgery:
//! a proof that the **canonical, unmodified** verifier accepts for a statement that is
//! false under leanVM's own semantics.
//!
//! See [`guest`] for the program, [`forge`] for the malicious witness generator, and the
//! `tests/exploit.rs` integration test for the end-to-end break.

use backend::*;
use lean_compiler::*;
use lean_prover::prove_execution::{prove_from_execution_result, prove_execution};
use lean_prover::verify_execution::verify_execution;
use lean_prover::default_whir_config;
use lean_vm::*;

pub mod forge;
pub mod guest;
pub mod isa_guest;

/// Honest run of the hand-written ISA program on `claim` (via the real runner + hint).
pub fn honest_isa_execution(bytecode: &Bytecode, claim: u32) -> Result<ExecutionResult, RunnerError> {
    try_execute_bytecode(
        bytecode,
        &public_input(claim),
        &isa_guest::honest_witness(bytecode),
        false,
    )
}

/// Honest prove + canonical verify of the hand-written ISA program.
pub fn prove_and_verify_isa_honest(bytecode: &Bytecode, claim: u32) -> bool {
    let proof = prove_execution(
        bytecode,
        &public_input(claim),
        &isa_guest::honest_witness(bytecode),
        &default_whir_config(STARTING_LOG_INV_RATE),
        false,
    )
    .expect("honest ISA prove failed");
    match verify_execution(bytecode, &public_input(claim), proof.proof) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("ISA honest verify rejected: {e:?}");
            false
        }
    }
}

/// Same low WHIR rate the leanVM prove/verify tests use; the PoC only needs a tiny trace.
pub const STARTING_LOG_INV_RATE: usize = 1;

/// Build the `[F; PUBLIC_INPUT_LEN]` public statement whose first cell is `claim`.
pub fn public_input(claim: u32) -> [F; PUBLIC_INPUT_LEN] {
    let mut out = [F::ZERO; PUBLIC_INPUT_LEN];
    out[0] = F::new(claim);
    out
}

/// Compile the guest program to bytecode.
pub fn compile_guest() -> Bytecode {
    compile_program(&ProgramSource::Raw(guest::GUEST_SOURCE.to_string()))
}

/// Run the honest runner on `claim`. Returns `Err` exactly when the honest program cannot
/// accept (e.g. the assert `fib(N) == claim` fails for a false `claim`).
pub fn honest_execution(bytecode: &Bytecode, claim: u32) -> Result<ExecutionResult, RunnerError> {
    try_execute_bytecode(
        bytecode,
        &public_input(claim),
        &ExecutionWitness::default(),
        false,
    )
}

/// Honest prove + verify against the canonical verifier. Used as the control (a true
/// statement really does produce a proof the verifier accepts).
pub fn prove_and_verify_honest(bytecode: &Bytecode, claim: u32) -> bool {
    let proof = prove_execution(
        bytecode,
        &public_input(claim),
        &ExecutionWitness::default(),
        &default_whir_config(STARTING_LOG_INV_RATE),
        false,
    )
    .expect("honest prove failed");
    verify_execution(bytecode, &public_input(claim), proof.proof).is_ok()
}

/// Prove from a (possibly forged) [`ExecutionResult`] and check the resulting proof with
/// the **canonical, unmodified** verifier. `claim` is the public statement submitted to
/// both the prover and the verifier. Returns `true` iff the verifier accepts.
///
/// This is the crux call: `verify_execution` here is leanVM's shipping verifier, byte for
/// byte. A `true` return for a false `claim` is the soundness break.
pub fn prove_forged_and_verify(bytecode: &Bytecode, forged: ExecutionResult, claim: u32) -> bool {
    let proof = prove_from_execution_result(
        bytecode,
        forged,
        &public_input(claim),
        &default_whir_config(STARTING_LOG_INV_RATE),
    )
    .expect("forged prove failed");
    verify_execution(bytecode, &public_input(claim), proof.proof).is_ok()
}
