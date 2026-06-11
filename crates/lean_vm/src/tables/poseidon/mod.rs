use std::any::TypeId;

use crate::*;
use crate::{execution::memory::MemoryAccess, tables::poseidon::trace_gen::generate_trace_rows_for_perm};
use backend::*;

/// Dispatch `mds_fft_16` through concrete types.
/// For `SymbolicExpression` we use the dense form so the zkDSL generator can
/// emit `dot_product_be` precompile calls instead of Karatsuba arithmetic.
#[inline(always)]
fn mds_air_16<A: PrimeCharacteristicRing + 'static>(state: &mut [A; WIDTH]) {
    if TypeId::of::<A>() == TypeId::of::<SymbolicExpression<KoalaBear>>() {
        dense_mat_vec_air_16(mds_dense_16(), state);
        return;
    }
    macro_rules! dispatch {
        ($t:ty) => {
            if TypeId::of::<A>() == TypeId::of::<$t>() {
                mds_fft_16::<$t>(unsafe { &mut *(state as *mut [A; WIDTH] as *mut [$t; WIDTH]) });
                return;
            }
        };
    }
    dispatch!(F);
    dispatch!(EF);
    dispatch!(FPacking<F>);
    dispatch!(EFPacking<EF>);
    unreachable!()
}

fn mds_dense_16() -> &'static [[F; 16]; 16] {
    use std::sync::OnceLock;
    static MAT: OnceLock<[[KoalaBear; 16]; 16]> = OnceLock::new();
    MAT.get_or_init(|| {
        let cols: [[F; 16]; 16] = std::array::from_fn(|j| {
            let mut e = [F::ZERO; 16];
            e[j] = F::ONE;
            mds_circ_16(&mut e);
            e
        });
        std::array::from_fn(|i| std::array::from_fn(|j| cols[j][i]))
    })
}

/// Add a `KoalaBear` constant to any AIR type.
#[inline(always)]
fn add_kb<A: 'static>(a: &mut A, value: F) {
    macro_rules! dispatch {
        ($t:ty) => {
            if TypeId::of::<A>() == TypeId::of::<$t>() {
                *unsafe { &mut *(a as *mut A as *mut $t) } += value;
                return;
            }
        };
    }
    dispatch!(F);
    dispatch!(EF);
    dispatch!(FPacking<F>);
    dispatch!(EFPacking<EF>);
    dispatch!(SymbolicExpression<KoalaBear>);
    unreachable!()
}

/// Multiply any AIR type by a `KoalaBear` constant.
#[inline(always)]
fn mul_kb<A: PrimeCharacteristicRing + 'static>(a: A, value: F) -> A {
    macro_rules! dispatch {
        ($t:ty) => {
            if TypeId::of::<A>() == TypeId::of::<$t>() {
                let r = unsafe { std::ptr::read(&a as *const A as *const $t) } * value;
                return unsafe { std::ptr::read(&r as *const $t as *const A) };
            }
        };
    }
    dispatch!(F);
    dispatch!(EF);
    dispatch!(FPacking<F>);
    dispatch!(EFPacking<EF>);
    dispatch!(SymbolicExpression<KoalaBear>);
    unreachable!()
}

mod trace_gen;
pub use trace_gen::{fill_trace_poseidon_16, fill_trace_poseidon_16_out4, fill_trace_poseidon_16_out8};

pub(super) const WIDTH: usize = 16;
const HALF_INITIAL_FULL_ROUNDS: usize = POSEIDON1_HALF_FULL_ROUNDS / 2;
const PARTIAL_ROUNDS: usize = POSEIDON1_PARTIAL_ROUNDS;
const HALF_FINAL_FULL_ROUNDS: usize = POSEIDON1_HALF_FULL_ROUNDS / 2;

// domainsep encoding: see `tables/mod.rs`.
pub const POSEIDON_DOMAINSEP_BASE: usize = 3;
pub const POSEIDON_FLAG_PERMUTE_SHIFT: usize = 1 << 1;
pub const POSEIDON_FLAG_OUT8_SHIFT: usize = 1 << 2;
pub const POSEIDON_FLAG_LEFT_SHIFT: usize = 1 << 3;
pub const POSEIDON_OFFSET_LEFT_SHIFT: usize = 1 << 4;

pub const POSEIDON_COL_MULTIPLICITY: ColIndex = 0;
pub const POSEIDON_COL_NU_B: ColIndex = 1;
pub const POSEIDON_COL_NU_C: ColIndex = 2;
pub const POSEIDON_COL_FLAG_LEFT: ColIndex = 3;
pub const POSEIDON_COL_OFFSET_LEFT: ColIndex = 4;
pub const POSEIDON_COL_ADDR_LEFT_LO: ColIndex = 5;
pub const POSEIDON_COL_ADDR_LEFT_HI: ColIndex = 6;
pub const POSEIDON_COL_INPUT_START: ColIndex = 7;
pub const POSEIDON_COL_OUT_LO: ColIndex = num_cols_poseidon_16() - 16;
pub const POSEIDON_COL_OUT_HI: ColIndex = num_cols_poseidon_16() - 8;
/// Non-committed columns ("virtual"):
pub const POSEIDON_COL_NU_A: ColIndex = num_cols_poseidon_16();
pub const POSEIDON_COL_DOMAINSEP: ColIndex = num_cols_poseidon_16() + 1;

pub const POSEIDON16_COMPRESS_HALF_NAME: &str = "poseidon16_compress_half";
pub const POSEIDON16_QUARTER_NAME: &str = "poseidon16_compress_quarter";
pub const POSEIDON16_HARDCODED_LEFT_NAME: &str = "poseidon16_compress_half_hardcoded_left";
pub const POSEIDON16_QUARTER_HARDCODED_LEFT_NAME: &str = "poseidon16_compress_quarter_hardcoded_left";
pub const POSEIDON16_PERMUTE_NAME: &str = "poseidon16_permute";
pub const POSEIDON16_PERMUTE_HALF_NAME: &str = "poseidon16_permute_half";
pub const POSEIDON16_PERMUTE_HALF_HARDCODED_LEFT_NAME: &str = "poseidon16_permute_half_hardcoded_left";
pub const ALL_POSEIDON16_NAMES: [&str; 7] = [
    POSEIDON16_COMPRESS_HALF_NAME,
    POSEIDON16_QUARTER_NAME,
    POSEIDON16_HARDCODED_LEFT_NAME,
    POSEIDON16_QUARTER_HARDCODED_LEFT_NAME,
    POSEIDON16_PERMUTE_NAME,
    POSEIDON16_PERMUTE_HALF_NAME,
    POSEIDON16_PERMUTE_HALF_HARDCODED_LEFT_NAME,
];
pub const HALF_DIGEST_LEN: usize = DIGEST_LEN / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poseidon16Precompile<const BUS: bool>;

impl<const BUS: bool> TableT for Poseidon16Precompile<BUS> {
    fn name(&self) -> &'static str {
        "poseidon16"
    }

    fn table(&self) -> Table {
        Table::poseidon16()
    }

    fn n_columns_total(&self) -> usize {
        num_cols_total_poseidon_16()
    }

    fn bus_interactions(&self) -> Vec<BusInteraction> {
        let mut buses = vec![BusInteraction {
            direction: BusDirection::Pull,
            multiplicity: BusMultiplicity::Column(POSEIDON_COL_MULTIPLICITY),
            domainsep: BusData::Column(POSEIDON_COL_DOMAINSEP),
            data: vec![
                BusData::Column(POSEIDON_COL_NU_A),
                BusData::Column(POSEIDON_COL_NU_B),
                BusData::Column(POSEIDON_COL_NU_C),
            ],
        }];
        buses.extend(memory_lookups_consecutive(
            POSEIDON_COL_ADDR_LEFT_LO,
            POSEIDON_COL_INPUT_START,
            HALF_DIGEST_LEN,
        ));
        buses.extend(memory_lookups_consecutive(
            POSEIDON_COL_ADDR_LEFT_HI,
            POSEIDON_COL_INPUT_START + HALF_DIGEST_LEN,
            HALF_DIGEST_LEN,
        ));
        buses.extend(memory_lookups_consecutive(
            POSEIDON_COL_NU_B,
            POSEIDON_COL_INPUT_START + DIGEST_LEN,
            DIGEST_LEN,
        ));
        buses.extend(memory_lookups_consecutive(
            POSEIDON_COL_NU_C,
            POSEIDON_COL_OUT_LO,
            DIGEST_LEN * 2,
        ));
        buses
    }

    fn padding_row(&self, zero_vec_ptr: usize, _null_hash_ptr: usize, null_permute_ptr: usize, _ending_pc: usize) -> Vec<F> {
        let mut row = vec![F::ZERO; num_cols_total_poseidon_16()];
        let ptrs: Vec<*mut F> = (0..num_cols_poseidon_16())
            .map(|i| unsafe { row.as_mut_ptr().add(i) })
            .collect();

        let perm: &mut Poseidon1Cols16<&mut F> = unsafe { &mut *(ptrs.as_ptr() as *mut Poseidon1Cols16<&mut F>) };
        perm.inputs.iter_mut().for_each(|x| **x = F::ZERO);
        *perm.multiplicity = F::ZERO;
        *perm.nu_b = F::from_usize(zero_vec_ptr);
        // permute16 result lookup reads all 16 cells of permute([0;16]); point at the 16-cell
        // permute-of-zero constant, NOT the 8-cell compress-of-zero (null_hash_ptr).
        *perm.nu_c = F::from_usize(null_permute_ptr);
        *perm.flag_left = F::ZERO;
        *perm.offset_left = F::ZERO;
        *perm.addr_left_lo = F::from_usize(zero_vec_ptr);
        *perm.addr_left_hi = F::from_usize(zero_vec_ptr + HALF_DIGEST_LEN);
        row[POSEIDON_COL_NU_A] = F::from_usize(zero_vec_ptr);
        // permute16: domainsep = BASE + FLAG_PERMUTE_SHIFT (permute=true, flag_left=0)
        row[POSEIDON_COL_DOMAINSEP] = F::from_usize(POSEIDON_DOMAINSEP_BASE + POSEIDON_FLAG_PERMUTE_SHIFT);

        generate_trace_rows_for_perm(perm);
        row
    }

    #[inline(always)]
    fn execute<M: MemoryAccess>(
        &self,
        arg_a: F,
        arg_b: F,
        index_res_a: F,
        args: PrecompileCompTimeArgs<usize>,
        ctx: &mut InstructionContext<'_, M>,
    ) -> Result<(), RunnerError> {
        let PrecompileCompTimeArgs::Poseidon16 {
            half_output,
            hardcoded_offset_left,
            permute,
        } = args
        else {
            unreachable!("Poseidon16 table called with non-Poseidon16 args");
        };
        debug_assert!(
            !half_output && permute,
            "non-permute16 mode leaked into base poseidon table (half_output={half_output}, permute={permute})"
        );
        let trace = ctx.traces.get_mut(&self.table()).unwrap();

        let arg_a_usize = arg_a.to_usize();
        let flag_hardcoded = hardcoded_offset_left.is_some();
        // Convention:
        //   flag_hardcoded = 0: left input = m[arg_a..arg_a+8] (split as [arg_a..+4], [arg_a+4..+8])
        //   flag_hardcoded = 1: left input = m[offset..offset+4] | m[arg_a..arg_a+4]
        let left_first_addr = hardcoded_offset_left.unwrap_or(arg_a_usize);
        let left_second_addr = if flag_hardcoded {
            arg_a_usize
        } else {
            arg_a_usize + HALF_DIGEST_LEN
        };
        let mut input = [F::ZERO; DIGEST_LEN * 2];
        ctx.memory
            .get_slice_into(left_first_addr, &mut input[..HALF_DIGEST_LEN])?;
        ctx.memory
            .get_slice_into(left_second_addr, &mut input[HALF_DIGEST_LEN..DIGEST_LEN])?;
        ctx.memory.get_slice_into(arg_b.to_usize(), &mut input[DIGEST_LEN..])?;

        // permute16: always permutation, write all 16 cells
        let permuted = poseidon16_permute(input);
        let res_addr = index_res_a.to_usize();
        ctx.memory.set_slice(res_addr, &permuted)?;

        let hardcoded_offset_left_val = hardcoded_offset_left.unwrap_or(0);

        trace.columns[POSEIDON_COL_MULTIPLICITY].push(F::ONE);
        trace.columns[POSEIDON_COL_NU_B].push(arg_b);
        trace.columns[POSEIDON_COL_NU_C].push(index_res_a);
        trace.columns[POSEIDON_COL_FLAG_LEFT].push(F::from_bool(flag_hardcoded));
        trace.columns[POSEIDON_COL_OFFSET_LEFT].push(F::from_usize(hardcoded_offset_left_val));
        trace.columns[POSEIDON_COL_ADDR_LEFT_LO].push(F::from_usize(left_first_addr));
        trace.columns[POSEIDON_COL_ADDR_LEFT_HI].push(F::from_usize(left_second_addr));
        for (i, value) in input.iter().enumerate() {
            trace.columns[POSEIDON_COL_INPUT_START + i].push(*value);
        }
        // Non-committed columns
        trace.columns[POSEIDON_COL_NU_A].push(arg_a);
        // permute16: permute=true always, flag_left may vary
        let domainsep = POSEIDON_DOMAINSEP_BASE
            + POSEIDON_FLAG_PERMUTE_SHIFT
            + POSEIDON_FLAG_LEFT_SHIFT * (flag_hardcoded as usize)
            + POSEIDON_OFFSET_LEFT_SHIFT * hardcoded_offset_left_val;
        trace.columns[POSEIDON_COL_DOMAINSEP].push(F::from_usize(domainsep));

        // the rest of the trace is filled at the end of the execution (to get parallelism + SIMD)

        Ok(())
    }
}

impl<const BUS: bool> Air for Poseidon16Precompile<BUS> {
    type ExtraData = ExtraDataForBuses<EF>;
    fn n_columns(&self) -> usize {
        num_cols_poseidon_16()
    }
    fn degree_air(&self) -> usize {
        // Pure permute16: no flag gates on outputs, degree-9 permutation body.
        9
    }
    fn low_degree_air(&self) -> Option<(usize, usize)> {
        Some((3, PARTIAL_ROUNDS))
    }
    fn n_shift_columns(&self) -> usize {
        0
    }
    fn n_constraints(&self) -> usize {
        2 * BUS as usize + 88
    }
    fn eval<AB: AirBuilder>(&self, builder: &mut AB, extra_data: &Self::ExtraData) {
        let cols: Poseidon1Cols16<AB::IF> = {
            let flat = builder.flat();
            let (prefix, shorts, suffix) = unsafe { flat.align_to::<Poseidon1Cols16<AB::IF>>() };
            debug_assert!(prefix.is_empty(), "Alignment should match");
            debug_assert!(suffix.is_empty(), "Alignment should match");
            debug_assert_eq!(shorts.len(), 1);
            unsafe { std::ptr::read(&shorts[0]) }
        };

        // permute16: permute is always true, so domainsep = BASE + FLAG_PERMUTE_SHIFT + flag_left terms
        let domainsep_reconstructed = AB::IF::from_usize(POSEIDON_DOMAINSEP_BASE + POSEIDON_FLAG_PERMUTE_SHIFT)
            + cols.flag_left * AB::F::from_usize(POSEIDON_FLAG_LEFT_SHIFT)
            + cols.flag_left * cols.offset_left * AB::F::from_usize(POSEIDON_OFFSET_LEFT_SHIFT);

        let one_minus_flag_left = AB::IF::ONE - cols.flag_left;
        let nu_a = cols.addr_left_hi - one_minus_flag_left * AB::F::from_usize(HALF_DIGEST_LEN);

        if BUS {
            eval_bus_virtual::<AB, EF>(
                builder,
                extra_data,
                cols.multiplicity,
                domainsep_reconstructed,
                &[nu_a, cols.nu_b, cols.nu_c],
            );
        } else {
            builder.declare_values(std::slice::from_ref(&cols.multiplicity));
            builder.declare_values(&[nu_a, cols.nu_b, cols.nu_c, domainsep_reconstructed]);
        }

        builder.assert_bool(cols.multiplicity);
        builder.assert_bool(cols.flag_left);

        builder.assert_zero(cols.flag_left * (cols.offset_left - cols.addr_left_lo));
        builder.assert_zero(one_minus_flag_left * (nu_a - cols.addr_left_lo));

        eval_poseidon1_16(builder, &cols)
    }
}

#[repr(C)]
#[derive(Debug)]
pub(super) struct Poseidon1Cols16<T> {
    pub multiplicity: T, // 0 = padding, 1 = active
    pub nu_b: T,
    pub nu_c: T,
    pub flag_left: T,
    pub offset_left: T,
    pub addr_left_lo: T,
    pub addr_left_hi: T,

    pub inputs: [T; WIDTH],
    pub beginning_full_rounds: [[T; WIDTH]; HALF_INITIAL_FULL_ROUNDS],
    pub partial_rounds: [T; PARTIAL_ROUNDS],
    pub ending_full_rounds: [[T; WIDTH]; HALF_FINAL_FULL_ROUNDS - 1],
    pub out_lo: [T; WIDTH / 2],
    pub out_hi: [T; WIDTH / 2],
}

fn eval_poseidon1_16<AB: AirBuilder>(builder: &mut AB, local: &Poseidon1Cols16<AB::IF>) {
    let mut state: [_; WIDTH] = local.inputs;

    let initial_constants = poseidon1_initial_constants();
    for round in 0..HALF_INITIAL_FULL_ROUNDS {
        eval_2_full_rounds_16(
            &mut state,
            &local.beginning_full_rounds[round],
            &initial_constants[2 * round],
            &initial_constants[2 * round + 1],
            builder,
        );
    }

    // --- Sparse partial rounds ---
    // Transition: add first-round constants, multiply by m_i
    builder.low_degree_block(&mut state, |b, state| {
        let state: &mut [AB::IF; WIDTH] = state.try_into().unwrap();

        let frc = poseidon1_sparse_first_round_constants();
        for (s, &c) in state.iter_mut().zip(frc.iter()) {
            add_kb(s, c);
        }
        dense_mat_vec_air_16(poseidon1_sparse_m_i(), state);

        let first_rows = poseidon1_sparse_first_row();
        let v_vecs = poseidon1_sparse_v();
        let scalar_rc = poseidon1_sparse_scalar_round_constants();
        for round in 0..PARTIAL_ROUNDS {
            // S-box on state[0]
            state[0] = state[0].cube();
            b.assert_eq_low(state[0], local.partial_rounds[round]);
            state[0] = local.partial_rounds[round];
            // Scalar round constant (not on last round)
            if round < PARTIAL_ROUNDS - 1 {
                add_kb(&mut state[0], scalar_rc[round]);
            }
            // Sparse matrix: new_s0 = dot(first_row, state), state[i] += old_s0 * v[i-1]
            sparse_mat_air_16(state, &first_rows[round], &v_vecs[round]);
        }
    });

    let final_constants = poseidon1_final_constants();
    for round in 0..HALF_FINAL_FULL_ROUNDS - 1 {
        eval_2_full_rounds_16(
            &mut state,
            &local.ending_full_rounds[round],
            &final_constants[2 * round],
            &final_constants[2 * round + 1],
            builder,
        );
    }

    eval_last_2_full_rounds_16(
        &mut state,
        &local.out_lo,
        &local.out_hi,
        &final_constants[2 * (HALF_FINAL_FULL_ROUNDS - 1)],
        &final_constants[2 * (HALF_FINAL_FULL_ROUNDS - 1) + 1],
        builder,
    );
}

pub const fn num_cols_poseidon_16() -> usize {
    size_of::<Poseidon1Cols16<u8>>()
}

pub const fn num_cols_total_poseidon_16() -> usize {
    // +2 for non-committed columns: POSEIDON_COL_INDEX_INPUT_LEFT, POSEIDON_COL_DOMAINSEP
    num_cols_poseidon_16() + 2
}

#[inline]
fn eval_2_full_rounds_16<AB: AirBuilder>(
    state: &mut [AB::IF; WIDTH],
    post_full_round: &[AB::IF; WIDTH],
    round_constants_1: &[F; WIDTH],
    round_constants_2: &[F; WIDTH],
    builder: &mut AB,
) {
    for (s, r) in state.iter_mut().zip(round_constants_1.iter()) {
        add_kb(s, *r);
        *s = s.cube();
    }
    mds_air_16(state);
    for (s, r) in state.iter_mut().zip(round_constants_2.iter()) {
        add_kb(s, *r);
        *s = s.cube();
    }
    mds_air_16(state);
    for (state_i, post_i) in state.iter_mut().zip(post_full_round) {
        builder.assert_eq(*state_i, *post_i);
        *state_i = *post_i;
    }
}

/// Final 2 full rounds for permute16 mode: feedforward is always OFF (permutation).
/// All 16 output cells are constrained: out_lo[i] = state[i], out_hi[i] = state[i+8].
#[inline]
fn eval_last_2_full_rounds_16<AB: AirBuilder>(
    state: &mut [AB::IF; WIDTH],
    out_lo: &[AB::IF; WIDTH / 2],
    out_hi: &[AB::IF; WIDTH / 2],
    round_constants_1: &[F; WIDTH],
    round_constants_2: &[F; WIDTH],
    builder: &mut AB,
) {
    for (s, r) in state.iter_mut().zip(round_constants_1.iter()) {
        add_kb(s, *r);
        *s = s.cube();
    }
    mds_air_16(state);
    for (s, r) in state.iter_mut().zip(round_constants_2.iter()) {
        add_kb(s, *r);
        *s = s.cube();
    }
    mds_air_16(state);
    // Pure permutation: no feedforward, constrain all 16 outputs.
    for i in 0..(WIDTH / 2) {
        builder.assert_zero(state[i] - out_lo[i]);
        builder.assert_zero(state[i + WIDTH / 2] - out_hi[i]);
    }
}

#[inline]
fn dense_mat_vec_air_16<A: PrimeCharacteristicRing + 'static>(mat: &[[F; 16]; 16], state: &mut [A; WIDTH]) {
    let input = *state;
    for i in 0..WIDTH {
        let mut acc = A::ZERO;
        for j in 0..WIDTH {
            acc += mul_kb(input[j], mat[i][j]);
        }
        state[i] = acc;
    }
}

#[inline]
fn sparse_mat_air_16<A: PrimeCharacteristicRing + 'static>(
    state: &mut [A; WIDTH],
    first_row: &[F; WIDTH],
    v: &[F; WIDTH],
) {
    let old_s0 = state[0];
    let mut new_s0 = A::ZERO;
    for j in 0..WIDTH {
        new_s0 += mul_kb(state[j], first_row[j]);
    }
    state[0] = new_s0;
    for i in 1..WIDTH {
        state[i] += mul_kb(old_s0, v[i - 1]);
    }
}

// ============================================================================
// Poseidon16Out4 — 4-cell-output compression table
// ============================================================================
//
// This table handles only the `out4` mode (half_output=true, permute=false).
// It drops the flag_out4/flag_out8/flag_permute committed columns (always
// constant for this mode) and shrinks the result memory lookup from 16 to 4.

/// Column-index constants for Poseidon1Cols16Out4.
/// MUST mirror the #[repr(C)] field order of Poseidon1Cols16Out4 exactly.
pub const POSEIDON_OUT4_COL_MULTIPLICITY: ColIndex = 0;
pub const POSEIDON_OUT4_COL_NU_B: ColIndex = 1;
pub const POSEIDON_OUT4_COL_NU_C: ColIndex = 2;
pub const POSEIDON_OUT4_COL_FLAG_LEFT: ColIndex = 3;
pub const POSEIDON_OUT4_COL_OFFSET_LEFT: ColIndex = 4;
pub const POSEIDON_OUT4_COL_ADDR_LEFT_LO: ColIndex = 5;
pub const POSEIDON_OUT4_COL_ADDR_LEFT_HI: ColIndex = 6;
pub const POSEIDON_OUT4_COL_INPUT_START: ColIndex = 7;
pub const POSEIDON_OUT4_COL_OUT_LO: ColIndex = num_cols_poseidon_16_out4() - HALF_DIGEST_LEN;
/// Virtual (non-committed) columns:
pub const POSEIDON_OUT4_COL_NU_A: ColIndex = num_cols_poseidon_16_out4();
pub const POSEIDON_OUT4_COL_DOMAINSEP: ColIndex = num_cols_poseidon_16_out4() + 1;

pub const fn num_cols_poseidon_16_out4() -> usize {
    size_of::<Poseidon1Cols16Out4<u8>>()
}

pub const fn num_cols_total_poseidon_16_out4() -> usize {
    // +2 for non-committed columns: NU_A and DOMAINSEP
    num_cols_poseidon_16_out4() + 2
}

/// Column layout for the out4 Poseidon table.
/// Field order here is the column order — must match POSEIDON_OUT4_COL_* constants.
#[repr(C)]
#[derive(Debug)]
pub struct Poseidon1Cols16Out4<T> {
    pub multiplicity: T,
    pub nu_b: T,
    pub nu_c: T,
    pub flag_left: T,
    pub offset_left: T,
    pub addr_left_lo: T,
    pub addr_left_hi: T,
    pub inputs: [T; WIDTH],
    pub beginning_full_rounds: [[T; WIDTH]; HALF_INITIAL_FULL_ROUNDS],
    pub partial_rounds: [T; PARTIAL_ROUNDS],
    pub ending_full_rounds: [[T; WIDTH]; HALF_FINAL_FULL_ROUNDS - 1],
    pub out_lo: [T; HALF_DIGEST_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poseidon16Out4Precompile<const BUS: bool>;

impl<const BUS: bool> TableT for Poseidon16Out4Precompile<BUS> {
    fn name(&self) -> &'static str {
        "poseidon16_out4"
    }

    fn table(&self) -> Table {
        Table::poseidon16_out4()
    }

    fn n_columns_total(&self) -> usize {
        num_cols_total_poseidon_16_out4()
    }

    fn bus_interactions(&self) -> Vec<BusInteraction> {
        let mut buses = vec![BusInteraction {
            direction: BusDirection::Pull,
            multiplicity: BusMultiplicity::Column(POSEIDON_OUT4_COL_MULTIPLICITY),
            domainsep: BusData::Column(POSEIDON_OUT4_COL_DOMAINSEP),
            data: vec![
                BusData::Column(POSEIDON_OUT4_COL_NU_A),
                BusData::Column(POSEIDON_OUT4_COL_NU_B),
                BusData::Column(POSEIDON_OUT4_COL_NU_C),
            ],
        }];
        // left-lo: 4 cells starting at INPUT_START
        buses.extend(memory_lookups_consecutive(
            POSEIDON_OUT4_COL_ADDR_LEFT_LO,
            POSEIDON_OUT4_COL_INPUT_START,
            HALF_DIGEST_LEN,
        ));
        // left-hi: 4 cells starting at INPUT_START + 4
        buses.extend(memory_lookups_consecutive(
            POSEIDON_OUT4_COL_ADDR_LEFT_HI,
            POSEIDON_OUT4_COL_INPUT_START + HALF_DIGEST_LEN,
            HALF_DIGEST_LEN,
        ));
        // right: 8 cells starting at INPUT_START + 8
        buses.extend(memory_lookups_consecutive(
            POSEIDON_OUT4_COL_NU_B,
            POSEIDON_OUT4_COL_INPUT_START + DIGEST_LEN,
            DIGEST_LEN,
        ));
        // result: only HALF_DIGEST_LEN (4) cells — the key difference from the base table
        buses.extend(memory_lookups_consecutive(
            POSEIDON_OUT4_COL_NU_C,
            POSEIDON_OUT4_COL_OUT_LO,
            HALF_DIGEST_LEN,
        ));
        buses
    }

    fn padding_row(&self, zero_vec_ptr: usize, null_hash_ptr: usize, _null_permute_ptr: usize, _ending_pc: usize) -> Vec<F> {
        let mut row = vec![F::ZERO; num_cols_total_poseidon_16_out4()];
        let ptrs: Vec<*mut F> = (0..num_cols_poseidon_16_out4())
            .map(|i| unsafe { row.as_mut_ptr().add(i) })
            .collect();

        let perm: &mut Poseidon1Cols16Out4<&mut F> =
            unsafe { &mut *(ptrs.as_ptr() as *mut Poseidon1Cols16Out4<&mut F>) };
        perm.inputs.iter_mut().for_each(|x| **x = F::ZERO);
        *perm.multiplicity = F::ZERO;
        *perm.nu_b = F::from_usize(zero_vec_ptr);
        // The 4-cell result lookup reads m[null_hash_ptr..null_hash_ptr+4], which holds
        // poseidon_compress([0;16])[..4] — matching the out_lo[0..4] filled below.
        *perm.nu_c = F::from_usize(null_hash_ptr);
        *perm.flag_left = F::ZERO;
        *perm.offset_left = F::ZERO;
        *perm.addr_left_lo = F::from_usize(zero_vec_ptr);
        *perm.addr_left_hi = F::from_usize(zero_vec_ptr + HALF_DIGEST_LEN);
        // Virtual columns
        row[POSEIDON_OUT4_COL_NU_A] = F::from_usize(zero_vec_ptr);
        row[POSEIDON_OUT4_COL_DOMAINSEP] = F::from_usize(POSEIDON_DOMAINSEP_BASE);

        trace_gen::generate_trace_rows_for_perm_out4(perm);
        row
    }

    #[inline(always)]
    fn execute<M: MemoryAccess>(
        &self,
        arg_a: F,
        arg_b: F,
        index_res_a: F,
        args: PrecompileCompTimeArgs<usize>,
        ctx: &mut InstructionContext<'_, M>,
    ) -> Result<(), RunnerError> {
        let PrecompileCompTimeArgs::Poseidon16 {
            half_output,
            hardcoded_offset_left,
            permute,
        } = args
        else {
            unreachable!("Poseidon16Out4 table called with non-Poseidon16 args");
        };
        debug_assert!(
            half_output && !permute,
            "out4 table received non-out4 mode (half_output={half_output}, permute={permute})"
        );

        let trace = ctx.traces.get_mut(&self.table()).unwrap();

        let arg_a_usize = arg_a.to_usize();
        let flag_hardcoded = hardcoded_offset_left.is_some();
        let left_first_addr = hardcoded_offset_left.unwrap_or(arg_a_usize);
        let left_second_addr = if flag_hardcoded {
            arg_a_usize
        } else {
            arg_a_usize + HALF_DIGEST_LEN
        };
        let mut input = [F::ZERO; DIGEST_LEN * 2];
        ctx.memory
            .get_slice_into(left_first_addr, &mut input[..HALF_DIGEST_LEN])?;
        ctx.memory
            .get_slice_into(left_second_addr, &mut input[HALF_DIGEST_LEN..DIGEST_LEN])?;
        ctx.memory.get_slice_into(arg_b.to_usize(), &mut input[DIGEST_LEN..])?;

        let output = poseidon16_compress(input);
        let res_addr = index_res_a.to_usize();
        ctx.memory.set_slice(res_addr, &output[..HALF_DIGEST_LEN])?;

        let hardcoded_offset_left_val = hardcoded_offset_left.unwrap_or(0);

        trace.columns[POSEIDON_OUT4_COL_MULTIPLICITY].push(F::ONE);
        trace.columns[POSEIDON_OUT4_COL_NU_B].push(arg_b);
        trace.columns[POSEIDON_OUT4_COL_NU_C].push(index_res_a);
        trace.columns[POSEIDON_OUT4_COL_FLAG_LEFT].push(F::from_bool(flag_hardcoded));
        trace.columns[POSEIDON_OUT4_COL_OFFSET_LEFT].push(F::from_usize(hardcoded_offset_left_val));
        trace.columns[POSEIDON_OUT4_COL_ADDR_LEFT_LO].push(F::from_usize(left_first_addr));
        trace.columns[POSEIDON_OUT4_COL_ADDR_LEFT_HI].push(F::from_usize(left_second_addr));
        for (i, value) in input.iter().enumerate() {
            trace.columns[POSEIDON_OUT4_COL_INPUT_START + i].push(*value);
        }
        // Non-committed columns
        trace.columns[POSEIDON_OUT4_COL_NU_A].push(arg_a);
        let domainsep = POSEIDON_DOMAINSEP_BASE
            + POSEIDON_FLAG_LEFT_SHIFT * (flag_hardcoded as usize)
            + POSEIDON_OFFSET_LEFT_SHIFT * hardcoded_offset_left_val;
        trace.columns[POSEIDON_OUT4_COL_DOMAINSEP].push(F::from_usize(domainsep));

        Ok(())
    }
}

impl<const BUS: bool> Air for Poseidon16Out4Precompile<BUS> {
    type ExtraData = ExtraDataForBuses<EF>;

    fn n_columns(&self) -> usize {
        num_cols_poseidon_16_out4()
    }

    fn degree_air(&self) -> usize {
        // The output constraints are raw degree-9 permutation (no flag gate on outputs).
        9
    }

    fn low_degree_air(&self) -> Option<(usize, usize)> {
        Some((3, PARTIAL_ROUNDS))
    }

    fn n_shift_columns(&self) -> usize {
        0
    }

    fn n_constraints(&self) -> usize {
        // 2*BUS (bus virtual) + 4 (bool + addr constraints) + 72 (permutation body)
        // = 2*BUS + 76
        2 * BUS as usize + 76
    }

    fn eval<AB: AirBuilder>(&self, builder: &mut AB, extra_data: &Self::ExtraData) {
        let cols: Poseidon1Cols16Out4<AB::IF> = {
            let flat = builder.flat();
            let (prefix, shorts, suffix) = unsafe { flat.align_to::<Poseidon1Cols16Out4<AB::IF>>() };
            debug_assert!(prefix.is_empty(), "Alignment should match");
            debug_assert!(suffix.is_empty(), "Alignment should match");
            debug_assert_eq!(shorts.len(), 1);
            unsafe { std::ptr::read(&shorts[0]) }
        };

        // domainsep for out4 mode: BASE + flag_left*LEFT_SHIFT + flag_left*offset_left*OFFSET_SHIFT
        // (no permute/out8 terms — matches what execute() pushes)
        let domainsep_reconstructed = AB::IF::from_usize(POSEIDON_DOMAINSEP_BASE)
            + cols.flag_left * AB::F::from_usize(POSEIDON_FLAG_LEFT_SHIFT)
            + cols.flag_left * cols.offset_left * AB::F::from_usize(POSEIDON_OFFSET_LEFT_SHIFT);

        let one_minus_flag_left = AB::IF::ONE - cols.flag_left;
        // nu_a = addr_left_hi - (1 - flag_left) * HALF_DIGEST_LEN
        let nu_a = cols.addr_left_hi - one_minus_flag_left * AB::F::from_usize(HALF_DIGEST_LEN);

        if BUS {
            eval_bus_virtual::<AB, EF>(
                builder,
                extra_data,
                cols.multiplicity,
                domainsep_reconstructed,
                &[nu_a, cols.nu_b, cols.nu_c],
            );
        } else {
            builder.declare_values(std::slice::from_ref(&cols.multiplicity));
            builder.declare_values(&[nu_a, cols.nu_b, cols.nu_c, domainsep_reconstructed]);
        }

        builder.assert_bool(cols.multiplicity);
        builder.assert_bool(cols.flag_left);

        builder.assert_zero(cols.flag_left * (cols.offset_left - cols.addr_left_lo));
        builder.assert_zero(one_minus_flag_left * (nu_a - cols.addr_left_lo));

        eval_poseidon1_16_out4(builder, &cols);
    }
}

fn eval_poseidon1_16_out4<AB: AirBuilder>(builder: &mut AB, local: &Poseidon1Cols16Out4<AB::IF>) {
    let mut state: [_; WIDTH] = local.inputs;

    let initial_constants = poseidon1_initial_constants();
    for round in 0..HALF_INITIAL_FULL_ROUNDS {
        eval_2_full_rounds_16(
            &mut state,
            &local.beginning_full_rounds[round],
            &initial_constants[2 * round],
            &initial_constants[2 * round + 1],
            builder,
        );
    }

    // Sparse partial rounds
    builder.low_degree_block(&mut state, |b, state| {
        let state: &mut [AB::IF; WIDTH] = state.try_into().unwrap();

        let frc = poseidon1_sparse_first_round_constants();
        for (s, &c) in state.iter_mut().zip(frc.iter()) {
            add_kb(s, c);
        }
        dense_mat_vec_air_16(poseidon1_sparse_m_i(), state);

        let first_rows = poseidon1_sparse_first_row();
        let v_vecs = poseidon1_sparse_v();
        let scalar_rc = poseidon1_sparse_scalar_round_constants();
        for round in 0..PARTIAL_ROUNDS {
            state[0] = state[0].cube();
            b.assert_eq_low(state[0], local.partial_rounds[round]);
            state[0] = local.partial_rounds[round];
            if round < PARTIAL_ROUNDS - 1 {
                add_kb(&mut state[0], scalar_rc[round]);
            }
            sparse_mat_air_16(state, &first_rows[round], &v_vecs[round]);
        }
    });

    let final_constants = poseidon1_final_constants();
    for round in 0..HALF_FINAL_FULL_ROUNDS - 1 {
        eval_2_full_rounds_16(
            &mut state,
            &local.ending_full_rounds[round],
            &final_constants[2 * round],
            &final_constants[2 * round + 1],
            builder,
        );
    }

    eval_last_2_full_rounds_16_out4(
        &local.inputs,
        &mut state,
        &local.out_lo,
        &final_constants[2 * (HALF_FINAL_FULL_ROUNDS - 1)],
        &final_constants[2 * (HALF_FINAL_FULL_ROUNDS - 1) + 1],
        builder,
    );
}

/// Final 2 full rounds for out4 mode: always compression (feedforward on),
/// constrain only out_lo[0..HALF_DIGEST_LEN]. No out_hi, no flags.
#[inline]
fn eval_last_2_full_rounds_16_out4<AB: AirBuilder>(
    initial_state: &[AB::IF; WIDTH],
    state: &mut [AB::IF; WIDTH],
    out_lo: &[AB::IF; HALF_DIGEST_LEN],
    round_constants_1: &[F; WIDTH],
    round_constants_2: &[F; WIDTH],
    builder: &mut AB,
) {
    for (s, r) in state.iter_mut().zip(round_constants_1.iter()) {
        add_kb(s, *r);
        *s = s.cube();
    }
    mds_air_16(state);
    for (s, r) in state.iter_mut().zip(round_constants_2.iter()) {
        add_kb(s, *r);
        *s = s.cube();
    }
    mds_air_16(state);
    // Compression feedforward: always active (no flag_permute gate)
    for i in 0..HALF_DIGEST_LEN {
        let value = state[i] + initial_state[i];
        builder.assert_zero(value - out_lo[i]);
    }
}

// ============================================================================
// Poseidon16Out8 — 8-cell-output table (compress_half + permute_half)
// ============================================================================
//
// This table handles the `out8` modes: half_output == permute.
//   (half=false, permute=false) => compress_half / compress_half_hardcoded_left  (feedforward ON)
//   (half=true,  permute=true)  => permute_half  / permute_half_hardcoded_left   (feedforward OFF)
// It keeps a committed `flag_permute` column to gate the feedforward, and the
// result memory lookup is DIGEST_LEN (8) cells.

/// Column-index constants for Poseidon1Cols16Out8.
/// MUST mirror the #[repr(C)] field order of Poseidon1Cols16Out8 exactly.
pub const POSEIDON_OUT8_COL_MULTIPLICITY: ColIndex = 0;
pub const POSEIDON_OUT8_COL_NU_B: ColIndex = 1;
pub const POSEIDON_OUT8_COL_NU_C: ColIndex = 2;
pub const POSEIDON_OUT8_COL_FLAG_LEFT: ColIndex = 3;
pub const POSEIDON_OUT8_COL_OFFSET_LEFT: ColIndex = 4;
pub const POSEIDON_OUT8_COL_ADDR_LEFT_LO: ColIndex = 5;
pub const POSEIDON_OUT8_COL_ADDR_LEFT_HI: ColIndex = 6;
pub const POSEIDON_OUT8_COL_FLAG_PERMUTE: ColIndex = 7;
pub const POSEIDON_OUT8_COL_INPUT_START: ColIndex = 8;
pub const POSEIDON_OUT8_COL_OUT_LO: ColIndex = num_cols_poseidon_16_out8() - DIGEST_LEN;
/// Virtual (non-committed) columns:
pub const POSEIDON_OUT8_COL_NU_A: ColIndex = num_cols_poseidon_16_out8();
pub const POSEIDON_OUT8_COL_DOMAINSEP: ColIndex = num_cols_poseidon_16_out8() + 1;

pub const fn num_cols_poseidon_16_out8() -> usize {
    size_of::<Poseidon1Cols16Out8<u8>>()
}

pub const fn num_cols_total_poseidon_16_out8() -> usize {
    // +2 for non-committed columns: NU_A and DOMAINSEP
    num_cols_poseidon_16_out8() + 2
}

/// Column layout for the out8 Poseidon table.
/// Field order here is the column order — must match POSEIDON_OUT8_COL_* constants.
#[repr(C)]
#[derive(Debug)]
pub struct Poseidon1Cols16Out8<T> {
    pub multiplicity: T,
    pub nu_b: T,
    pub nu_c: T,
    pub flag_left: T,
    pub offset_left: T,
    pub addr_left_lo: T,
    pub addr_left_hi: T,
    pub flag_permute: T,
    pub inputs: [T; WIDTH],
    pub beginning_full_rounds: [[T; WIDTH]; HALF_INITIAL_FULL_ROUNDS],
    pub partial_rounds: [T; PARTIAL_ROUNDS],
    pub ending_full_rounds: [[T; WIDTH]; HALF_FINAL_FULL_ROUNDS - 1],
    pub out_lo: [T; DIGEST_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poseidon16Out8Precompile<const BUS: bool>;

impl<const BUS: bool> TableT for Poseidon16Out8Precompile<BUS> {
    fn name(&self) -> &'static str {
        "poseidon16_out8"
    }

    fn table(&self) -> Table {
        Table::poseidon16_out8()
    }

    fn n_columns_total(&self) -> usize {
        num_cols_total_poseidon_16_out8()
    }

    fn bus_interactions(&self) -> Vec<BusInteraction> {
        let mut buses = vec![BusInteraction {
            direction: BusDirection::Pull,
            multiplicity: BusMultiplicity::Column(POSEIDON_OUT8_COL_MULTIPLICITY),
            domainsep: BusData::Column(POSEIDON_OUT8_COL_DOMAINSEP),
            data: vec![
                BusData::Column(POSEIDON_OUT8_COL_NU_A),
                BusData::Column(POSEIDON_OUT8_COL_NU_B),
                BusData::Column(POSEIDON_OUT8_COL_NU_C),
            ],
        }];
        // left-lo: 4 cells starting at INPUT_START
        buses.extend(memory_lookups_consecutive(
            POSEIDON_OUT8_COL_ADDR_LEFT_LO,
            POSEIDON_OUT8_COL_INPUT_START,
            HALF_DIGEST_LEN,
        ));
        // left-hi: 4 cells starting at INPUT_START + 4
        buses.extend(memory_lookups_consecutive(
            POSEIDON_OUT8_COL_ADDR_LEFT_HI,
            POSEIDON_OUT8_COL_INPUT_START + HALF_DIGEST_LEN,
            HALF_DIGEST_LEN,
        ));
        // right: 8 cells starting at INPUT_START + 8
        buses.extend(memory_lookups_consecutive(
            POSEIDON_OUT8_COL_NU_B,
            POSEIDON_OUT8_COL_INPUT_START + DIGEST_LEN,
            DIGEST_LEN,
        ));
        // result: DIGEST_LEN (8) cells — the key difference from the base table
        buses.extend(memory_lookups_consecutive(
            POSEIDON_OUT8_COL_NU_C,
            POSEIDON_OUT8_COL_OUT_LO,
            DIGEST_LEN,
        ));
        buses
    }

    fn padding_row(&self, zero_vec_ptr: usize, null_hash_ptr: usize, _null_permute_ptr: usize, _ending_pc: usize) -> Vec<F> {
        let mut row = vec![F::ZERO; num_cols_total_poseidon_16_out8()];
        let ptrs: Vec<*mut F> = (0..num_cols_poseidon_16_out8())
            .map(|i| unsafe { row.as_mut_ptr().add(i) })
            .collect();

        let perm: &mut Poseidon1Cols16Out8<&mut F> =
            unsafe { &mut *(ptrs.as_ptr() as *mut Poseidon1Cols16Out8<&mut F>) };
        perm.inputs.iter_mut().for_each(|x| **x = F::ZERO);
        *perm.multiplicity = F::ZERO;
        *perm.nu_b = F::from_usize(zero_vec_ptr);
        // Compress sub-mode (flag_permute=0): the 8-cell result lookup reads
        // m[null_hash_ptr..null_hash_ptr+8], which holds poseidon_compress([0;16])[..8].
        *perm.nu_c = F::from_usize(null_hash_ptr);
        *perm.flag_left = F::ZERO;
        *perm.offset_left = F::ZERO;
        *perm.addr_left_lo = F::from_usize(zero_vec_ptr);
        *perm.addr_left_hi = F::from_usize(zero_vec_ptr + HALF_DIGEST_LEN);
        *perm.flag_permute = F::ZERO;
        // Virtual columns
        row[POSEIDON_OUT8_COL_NU_A] = F::from_usize(zero_vec_ptr);
        // compress sub-mode: flag_permute=0, flag_left=0 => domainsep = BASE
        row[POSEIDON_OUT8_COL_DOMAINSEP] = F::from_usize(POSEIDON_DOMAINSEP_BASE);

        trace_gen::generate_trace_rows_for_perm_out8(perm);
        row
    }

    #[inline(always)]
    fn execute<M: MemoryAccess>(
        &self,
        arg_a: F,
        arg_b: F,
        index_res_a: F,
        args: PrecompileCompTimeArgs<usize>,
        ctx: &mut InstructionContext<'_, M>,
    ) -> Result<(), RunnerError> {
        let PrecompileCompTimeArgs::Poseidon16 {
            half_output,
            hardcoded_offset_left,
            permute,
        } = args
        else {
            unreachable!("Poseidon16Out8 table called with non-Poseidon16 args");
        };
        debug_assert!(
            half_output == permute,
            "out8 table got non-out8 mode (half_output={half_output}, permute={permute})"
        );

        let trace = ctx.traces.get_mut(&self.table()).unwrap();

        let arg_a_usize = arg_a.to_usize();
        let flag_hardcoded = hardcoded_offset_left.is_some();
        let left_first_addr = hardcoded_offset_left.unwrap_or(arg_a_usize);
        let left_second_addr = if flag_hardcoded {
            arg_a_usize
        } else {
            arg_a_usize + HALF_DIGEST_LEN
        };
        let mut input = [F::ZERO; DIGEST_LEN * 2];
        ctx.memory
            .get_slice_into(left_first_addr, &mut input[..HALF_DIGEST_LEN])?;
        ctx.memory
            .get_slice_into(left_second_addr, &mut input[HALF_DIGEST_LEN..DIGEST_LEN])?;
        ctx.memory.get_slice_into(arg_b.to_usize(), &mut input[DIGEST_LEN..])?;

        let res_addr = index_res_a.to_usize();
        if permute {
            // permute_half: feedforward OFF, write first 8 cells
            let permuted = poseidon16_permute(input);
            ctx.memory.set_slice(res_addr, &permuted[..DIGEST_LEN])?;
        } else {
            // compress_half: feedforward ON, write first 8 cells
            let output = poseidon16_compress(input);
            ctx.memory.set_slice(res_addr, &output[..DIGEST_LEN])?;
        }

        let hardcoded_offset_left_val = hardcoded_offset_left.unwrap_or(0);

        trace.columns[POSEIDON_OUT8_COL_MULTIPLICITY].push(F::ONE);
        trace.columns[POSEIDON_OUT8_COL_NU_B].push(arg_b);
        trace.columns[POSEIDON_OUT8_COL_NU_C].push(index_res_a);
        trace.columns[POSEIDON_OUT8_COL_FLAG_LEFT].push(F::from_bool(flag_hardcoded));
        trace.columns[POSEIDON_OUT8_COL_OFFSET_LEFT].push(F::from_usize(hardcoded_offset_left_val));
        trace.columns[POSEIDON_OUT8_COL_ADDR_LEFT_LO].push(F::from_usize(left_first_addr));
        trace.columns[POSEIDON_OUT8_COL_ADDR_LEFT_HI].push(F::from_usize(left_second_addr));
        trace.columns[POSEIDON_OUT8_COL_FLAG_PERMUTE].push(F::from_bool(permute));
        for (i, value) in input.iter().enumerate() {
            trace.columns[POSEIDON_OUT8_COL_INPUT_START + i].push(*value);
        }
        // Non-committed columns
        trace.columns[POSEIDON_OUT8_COL_NU_A].push(arg_a);
        // Note: NO FLAG_OUT8_SHIFT term (this table is identified by its bus slot, not by domainsep flag)
        let domainsep = POSEIDON_DOMAINSEP_BASE
            + POSEIDON_FLAG_PERMUTE_SHIFT * (permute as usize)
            + POSEIDON_FLAG_LEFT_SHIFT * (flag_hardcoded as usize)
            + POSEIDON_OFFSET_LEFT_SHIFT * hardcoded_offset_left_val;
        trace.columns[POSEIDON_OUT8_COL_DOMAINSEP].push(F::from_usize(domainsep));

        Ok(())
    }
}

impl<const BUS: bool> Air for Poseidon16Out8Precompile<BUS> {
    type ExtraData = ExtraDataForBuses<EF>;

    fn n_columns(&self) -> usize {
        num_cols_poseidon_16_out8()
    }

    fn degree_air(&self) -> usize {
        // Feedforward gated by (1 - flag_permute): degree-9 permutation * degree-1 flag = degree 10.
        // But flag_permute is a committed column (linear), so the gated output constraint is:
        //   state[i] + (1 - flag_permute)*initial_state[i] - out_lo[i] = 0
        // where state[i] is degree-9. The feedforward term is degree-9 * 1 = degree 9,
        // so the full expression is degree 9. No additional gate multiplier.
        9
    }

    fn low_degree_air(&self) -> Option<(usize, usize)> {
        Some((3, PARTIAL_ROUNDS))
    }

    fn n_shift_columns(&self) -> usize {
        0
    }

    fn n_constraints(&self) -> usize {
        2 * BUS as usize + 81
    }

    fn eval<AB: AirBuilder>(&self, builder: &mut AB, extra_data: &Self::ExtraData) {
        let cols: Poseidon1Cols16Out8<AB::IF> = {
            let flat = builder.flat();
            let (prefix, shorts, suffix) = unsafe { flat.align_to::<Poseidon1Cols16Out8<AB::IF>>() };
            debug_assert!(prefix.is_empty(), "Alignment should match");
            debug_assert!(suffix.is_empty(), "Alignment should match");
            debug_assert_eq!(shorts.len(), 1);
            unsafe { std::ptr::read(&shorts[0]) }
        };

        // domainsep: BASE + flag_permute*FLAG_PERMUTE_SHIFT + flag_left*LEFT_SHIFT + flag_left*offset_left*OFFSET_SHIFT
        // (no FLAG_OUT8_SHIFT term — matches execute())
        let domainsep_reconstructed = AB::IF::from_usize(POSEIDON_DOMAINSEP_BASE)
            + cols.flag_permute * AB::F::from_usize(POSEIDON_FLAG_PERMUTE_SHIFT)
            + cols.flag_left * AB::F::from_usize(POSEIDON_FLAG_LEFT_SHIFT)
            + cols.flag_left * cols.offset_left * AB::F::from_usize(POSEIDON_OFFSET_LEFT_SHIFT);

        let one_minus_flag_left = AB::IF::ONE - cols.flag_left;
        // nu_a = addr_left_hi - (1 - flag_left) * HALF_DIGEST_LEN
        let nu_a = cols.addr_left_hi - one_minus_flag_left * AB::F::from_usize(HALF_DIGEST_LEN);

        if BUS {
            eval_bus_virtual::<AB, EF>(
                builder,
                extra_data,
                cols.multiplicity,
                domainsep_reconstructed,
                &[nu_a, cols.nu_b, cols.nu_c],
            );
        } else {
            builder.declare_values(std::slice::from_ref(&cols.multiplicity));
            builder.declare_values(&[nu_a, cols.nu_b, cols.nu_c, domainsep_reconstructed]);
        }

        builder.assert_bool(cols.multiplicity);
        builder.assert_bool(cols.flag_left);
        builder.assert_bool(cols.flag_permute);

        builder.assert_zero(cols.flag_left * (cols.offset_left - cols.addr_left_lo));
        builder.assert_zero(one_minus_flag_left * (nu_a - cols.addr_left_lo));

        eval_poseidon1_16_out8(builder, &cols);
    }
}

fn eval_poseidon1_16_out8<AB: AirBuilder>(builder: &mut AB, local: &Poseidon1Cols16Out8<AB::IF>) {
    let mut state: [_; WIDTH] = local.inputs;

    let initial_constants = poseidon1_initial_constants();
    for round in 0..HALF_INITIAL_FULL_ROUNDS {
        eval_2_full_rounds_16(
            &mut state,
            &local.beginning_full_rounds[round],
            &initial_constants[2 * round],
            &initial_constants[2 * round + 1],
            builder,
        );
    }

    // Sparse partial rounds
    builder.low_degree_block(&mut state, |b, state| {
        let state: &mut [AB::IF; WIDTH] = state.try_into().unwrap();

        let frc = poseidon1_sparse_first_round_constants();
        for (s, &c) in state.iter_mut().zip(frc.iter()) {
            add_kb(s, c);
        }
        dense_mat_vec_air_16(poseidon1_sparse_m_i(), state);

        let first_rows = poseidon1_sparse_first_row();
        let v_vecs = poseidon1_sparse_v();
        let scalar_rc = poseidon1_sparse_scalar_round_constants();
        for round in 0..PARTIAL_ROUNDS {
            state[0] = state[0].cube();
            b.assert_eq_low(state[0], local.partial_rounds[round]);
            state[0] = local.partial_rounds[round];
            if round < PARTIAL_ROUNDS - 1 {
                add_kb(&mut state[0], scalar_rc[round]);
            }
            sparse_mat_air_16(state, &first_rows[round], &v_vecs[round]);
        }
    });

    let final_constants = poseidon1_final_constants();
    for round in 0..HALF_FINAL_FULL_ROUNDS - 1 {
        eval_2_full_rounds_16(
            &mut state,
            &local.ending_full_rounds[round],
            &final_constants[2 * round],
            &final_constants[2 * round + 1],
            builder,
        );
    }

    eval_last_2_full_rounds_16_out8(
        &local.inputs,
        &mut state,
        &local.out_lo,
        local.flag_permute,
        &final_constants[2 * (HALF_FINAL_FULL_ROUNDS - 1)],
        &final_constants[2 * (HALF_FINAL_FULL_ROUNDS - 1) + 1],
        builder,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend::get_symbolic_constraints_and_bus_data_values;

    /// Verify that `n_constraints()` exactly matches the actual number of constraints produced
    /// by `eval()`, as counted symbolically.  This test must pass for the proof system to work.
    #[test]
    fn test_n_constraints_base_permute16() {
        let air = Poseidon16Precompile::<false>;
        let (constraints, _, _) = get_symbolic_constraints_and_bus_data_values::<F, _>(&air);
        assert_eq!(
            air.n_constraints(),
            constraints.len(),
            "Poseidon16 (permute16) n_constraints() mismatch: declared {}, actual {}",
            air.n_constraints(),
            constraints.len()
        );
        assert_eq!(air.n_constraints(), 88, "base permute16 n_constraints sanity check");
    }

    #[test]
    fn test_n_constraints_out4() {
        let air = Poseidon16Out4Precompile::<false>;
        let (constraints, _, _) = get_symbolic_constraints_and_bus_data_values::<F, _>(&air);
        assert_eq!(
            air.n_constraints(),
            constraints.len(),
            "Poseidon16Out4 n_constraints() mismatch: declared {}, actual {}",
            air.n_constraints(),
            constraints.len()
        );
        assert_eq!(air.n_constraints(), 76, "out4 n_constraints sanity check");
    }

    #[test]
    fn test_n_constraints_out8() {
        let air = Poseidon16Out8Precompile::<false>;
        let (constraints, _, _) = get_symbolic_constraints_and_bus_data_values::<F, _>(&air);
        assert_eq!(
            air.n_constraints(),
            constraints.len(),
            "Poseidon16Out8 n_constraints() mismatch: declared {}, actual {}",
            air.n_constraints(),
            constraints.len()
        );
        assert_eq!(air.n_constraints(), 81, "out8 n_constraints sanity check");
    }

    #[test]
    fn test_num_cols_out8_align_to_invariant() {
        assert_eq!(
            num_cols_poseidon_16_out8(),
            size_of::<Poseidon1Cols16Out8<u8>>(),
            "num_cols_poseidon_16_out8() must equal size_of::<Poseidon1Cols16Out8<u8>>()"
        );
    }
}

/// Final 2 full rounds for out8 mode: feedforward gated by (1 - flag_permute).
/// Constrains out_lo[0..DIGEST_LEN]: out_lo[i] = state[i] + (1 - flag_permute)*initial_state[i].
/// No out_hi. The constraint is degree 9 (state is degree-9, flag_permute is linear).
#[inline]
fn eval_last_2_full_rounds_16_out8<AB: AirBuilder>(
    initial_state: &[AB::IF; WIDTH],
    state: &mut [AB::IF; WIDTH],
    out_lo: &[AB::IF; DIGEST_LEN],
    flag_permute: AB::IF,
    round_constants_1: &[F; WIDTH],
    round_constants_2: &[F; WIDTH],
    builder: &mut AB,
) {
    for (s, r) in state.iter_mut().zip(round_constants_1.iter()) {
        add_kb(s, *r);
        *s = s.cube();
    }
    mds_air_16(state);
    for (s, r) in state.iter_mut().zip(round_constants_2.iter()) {
        add_kb(s, *r);
        *s = s.cube();
    }
    mds_air_16(state);
    // Feedforward: active when !flag_permute (compression), OFF when flag_permute (permute_half).
    let feedforward = AB::IF::ONE - flag_permute;
    for i in 0..DIGEST_LEN {
        builder.assert_zero(state[i] + feedforward * initial_state[i] - out_lo[i]);
    }
}
