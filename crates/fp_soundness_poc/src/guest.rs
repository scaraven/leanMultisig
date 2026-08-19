//! The guest program for the frame-pointer soundness PoC.
//!
//! `main` reads a claimed value from the public input (`public_input[0]`, via the
//! `p = 0; p[0]` zero-pointer idiom), computes `fib(N)` through a **real, non-inline**
//! function call, and asserts the two are equal. Because `fib` is a real call, its
//! `return` lowers to `JUMP dest=m[fp+.], updated_fp=m[fp+1]` — a jump whose new frame
//! pointer is read from a prover-controlled memory cell. That is the single seam the
//! forge (see `crate::forge`) uses to install an out-of-range `fp` the honest runner
//! would never produce.
//!
//! Honest semantics: the proof exists iff `public_input[0] == fib(N)`.

/// `fib(N)` for the `N` baked into [`GUEST_SOURCE`]. Keep in sync with the source below.
pub const N: usize = 10;

/// The true value of `fib(N)` (fib: 0,1,1,2,3,5,8,13,21,34,55 → fib(10) = 55).
pub const FIB_N: u32 = 55;

/// zkDSL source. `N` is a compile-time constant so the loop is unrolled and the program
/// touches no precompiles — the Poseidon and extension tables stay empty padding and the
/// forge only ever has to reason about the execution table.
///
/// The `pad` loop only exists to push the execution table past `MIN_LOG_N_ROWS_PER_TABLE`
/// (256 rows) so the WHIR prover accepts the trace; it is straight-line (`unroll`), so it
/// adds no stack frames and leaves the `fib` call/return the forge targets untouched.
pub const GUEST_SOURCE: &str = r#"
from snark_lib import *

N = 10
PAD = 300

def main():
    p = 0
    claim = p[0]
    pad = Array(PAD + 1)
    pad[0] = 0
    for i in unroll(0, PAD):
        pad[i + 1] = pad[i] + 1
    r = fib()
    assert r == claim
    return

def fib():
    buff = Array(N + 2)
    buff[0] = 0
    buff[1] = 1
    for j in unroll(2, N + 2):
        buff[j] = buff[j - 1] + buff[j - 2]
    return buff[N]
"#;
