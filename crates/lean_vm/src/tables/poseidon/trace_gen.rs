use tracing::instrument;

use crate::{F, tables::poseidon::{WIDTH, Poseidon1Cols16}};
use backend::*;

// ============================================================================
// Generic trace filler — one function for all three table variants
// ============================================================================

/// Fill the AIR trace for the Poseidon16 table identified by `(OUT_WIDTH, FLAG_LEN)`.
/// Dispatched from lean_prover for each of the three tables.
///
/// `FLAG_LEN=0` → permute16 or out4 (no committed flag_permute column)
/// `FLAG_LEN=1` → out8 (committed flag_permute column at col 7)
#[instrument(name = "generate Poseidon16 AIR trace", skip_all)]
pub fn fill_trace_poseidon_16<const OUT_WIDTH: usize, const FLAG_LEN: usize>(trace: &mut [Vec<F>]) {
    let n = trace.iter().map(|col| col.len()).max().unwrap();
    for col in trace.iter_mut() {
        if col.len() != n {
            col.resize(n, F::ZERO);
        }
    }

    let m = n - (n % packing_width::<F>());
    let trace_packed: Vec<_> = trace.iter().map(|col| FPacking::<F>::pack_slice(&col[..m])).collect();

    let n_cols: usize = super::num_cols::<OUT_WIDTH, FLAG_LEN>();

    let cols: &[&[FPacking<F>]] = &trace_packed[..n_cols];
    parallel::for_each_index(m / packing_width::<F>(), |i| {
        let ptrs: Vec<*mut FPacking<F>> =
            cols.iter().map(|c| unsafe { (c.as_ptr() as *mut FPacking<F>).add(i) }).collect();
        let perm: &mut Poseidon1Cols16<&mut FPacking<F>, OUT_WIDTH, FLAG_LEN> =
            unsafe { &mut *(ptrs.as_ptr() as *mut Poseidon1Cols16<&mut FPacking<F>, OUT_WIDTH, FLAG_LEN>) };
        generate_trace_rows_for_perm(perm);
    });

    let cols: &[Vec<F>] = &trace[..n_cols];
    for i in m..n {
        let ptrs: Vec<*mut F> = cols.iter().map(|c| unsafe { (c.as_ptr() as *mut F).add(i) }).collect();
        let perm: &mut Poseidon1Cols16<&mut F, OUT_WIDTH, FLAG_LEN> =
            unsafe { &mut *(ptrs.as_ptr() as *mut Poseidon1Cols16<&mut F, OUT_WIDTH, FLAG_LEN>) };
        generate_trace_rows_for_perm(perm);
    }
}

pub(super) fn generate_trace_rows_for_perm<F: Algebra<KoalaBear> + Copy, const OUT_WIDTH: usize, const FLAG_LEN: usize>(
    perm: &mut Poseidon1Cols16<&mut F, OUT_WIDTH, FLAG_LEN>,
) {
    let inputs: [F; WIDTH] = std::array::from_fn(|i| *perm.inputs[i]);
    let mut state = inputs;

    for (full_round, constants) in perm
        .beginning_full_rounds
        .iter_mut()
        .zip(poseidon1_initial_constants().chunks_exact(2))
    {
        generate_2_full_round(&mut state, full_round, &constants[0], &constants[1]);
    }

    // Sparse partial rounds
    let frc = poseidon1_sparse_first_round_constants();
    for (s, &c) in state.iter_mut().zip(frc.iter()) {
        *s += c;
    }
    let m_i = poseidon1_sparse_m_i();
    let input_for_mi = state;
    for i in 0..WIDTH {
        let row: [F; WIDTH] = m_i[i].map(F::from);
        state[i] = F::dot_product(&input_for_mi, &row);
    }

    let first_rows = poseidon1_sparse_first_row();
    let v_vecs = poseidon1_sparse_v();
    let scalar_rc = poseidon1_sparse_scalar_round_constants();
    let n_partial = perm.partial_rounds.len();
    for round in 0..n_partial {
        state[0] = state[0].cube();
        *perm.partial_rounds[round] = state[0];
        if round < n_partial - 1 {
            state[0] += scalar_rc[round];
        }
        let old_s0 = state[0];
        let row: [F; WIDTH] = first_rows[round].map(F::from);
        let new_s0 = F::dot_product(&state, &row);
        state[0] = new_s0;
        for i in 1..WIDTH {
            state[i] += old_s0 * v_vecs[round][i - 1];
        }
    }

    let n_ending_full_rounds = perm.ending_full_rounds.len();
    for (full_round, constants) in perm
        .ending_full_rounds
        .iter_mut()
        .zip(poseidon1_final_constants().chunks_exact(2))
    {
        generate_2_full_round(&mut state, full_round, &constants[0], &constants[1]);
    }

    // For FLAG_LEN=1 (out8): read the runtime flag_permute to determine feedforward mode.
    // For FLAG_LEN=0:
    //   OUT_WIDTH=16 → permute16: feedforward OFF → flag_permute_hint = F::ONE (coeff = 1-1 = 0)
    //   OUT_WIDTH=4  → out4:      feedforward ON  → flag_permute_hint = F::ZERO (coeff = 1-0 = 1)
    // This encoding uses the fact that feedforward coeff = (1 - flag_permute_hint).
    let flag_permute: F = if FLAG_LEN == 1 {
        *perm.flag_permute[0]
    } else if OUT_WIDTH == 16 {
        F::from(KoalaBear::ONE)   // permute16: FF OFF → coeff = (1-1) = 0
    } else {
        F::from(KoalaBear::ZERO)  // out4: FF ON → coeff = (1-0) = 1
    };

    generate_last_2_full_rounds_generic(
        &mut state,
        &inputs,
        &mut perm.out,
        flag_permute,
        &poseidon1_final_constants()[2 * n_ending_full_rounds],
        &poseidon1_final_constants()[2 * n_ending_full_rounds + 1],
    );
}

#[inline]
fn generate_2_full_round<F: Algebra<KoalaBear> + Copy>(
    state: &mut [F; WIDTH],
    post_full_round: &mut [&mut F; WIDTH],
    round_constants_1: &[KoalaBear; WIDTH],
    round_constants_2: &[KoalaBear; WIDTH],
) {
    for (state_i, const_i) in state.iter_mut().zip(round_constants_1) {
        *state_i += *const_i;
        *state_i = state_i.cube();
    }
    mds_circ_16(state);

    for (state_i, const_i) in state.iter_mut().zip(round_constants_2.iter()) {
        *state_i += *const_i;
        *state_i = state_i.cube();
    }
    mds_circ_16(state);

    post_full_round.iter_mut().zip(*state).for_each(|(post, x)| {
        **post = x;
    });
}

/// Generic final 2 full rounds for trace generation.
///
/// `flag_permute` encodes the feedforward mode:
///   F::ONE  → feedforward OFF (pure permutation): write state[i] into out[i].
///   F::ZERO → feedforward ON  (compression):      write state[i] + inputs[i] into out[i].
///   Runtime → out8 gated:                         write state[i] + (1-flag_permute)*inputs[i].
///
/// All three cases are unified by the single formula: out[i] = state[i] + (1-flag_permute)*inputs[i].
#[inline]
fn generate_last_2_full_rounds_generic<F: Algebra<KoalaBear> + Copy, const OUT_WIDTH: usize>(
    state: &mut [F; WIDTH],
    inputs: &[F; WIDTH],
    out: &mut [&mut F; OUT_WIDTH],
    flag_permute: F,
    round_constants_1: &[KoalaBear; WIDTH],
    round_constants_2: &[KoalaBear; WIDTH],
) {
    for (state_i, const_i) in state.iter_mut().zip(round_constants_1) {
        *state_i += *const_i;
        *state_i = state_i.cube();
    }
    mds_circ_16(state);

    for (state_i, const_i) in state.iter_mut().zip(round_constants_2.iter()) {
        *state_i += *const_i;
        *state_i = state_i.cube();
    }
    mds_circ_16(state);

    // Unified feedforward: coeff = (1 - flag_permute).
    let one = F::from(KoalaBear::ONE);
    for i in 0..OUT_WIDTH {
        *out[i] = state[i] + (one - flag_permute) * inputs[i];
    }
}
