use std::any::TypeId;

use crate::*;
use crate::execution::memory::MemoryAccess;
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
pub use trace_gen::fill_trace_poseidon_16;

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

// FEEDFORWARD const-param values.
/// Feedforward OFF (pure permutation, e.g., permute16 and permute_half).
pub const FF_OFF: u8 = 0;
/// Feedforward ON always (e.g., out4 / compress_quarter).
pub const FF_ON: u8 = 1;
/// Feedforward gated by `flag_permute` (0=compress, 1=permute; e.g., out8).
pub const FF_GATED: u8 = 2;

// ============================================================================
// Generic Cols struct (stable Rust: FLAG_LEN is 0 or 1)
// ============================================================================
//
// `FLAG_LEN=0` → `flag_permute: [T; 0]` is a ZST (zero bytes in #[repr(C)]).
// `FLAG_LEN=1` → `flag_permute: [T; 1]` is one committed column.
//
// Monomorphizations:
//   permute16: Poseidon1Cols16<T, 16, 0>  (FLAG_LEN=0, OUT_WIDTH=16)
//   out4:      Poseidon1Cols16<T,  4, 0>  (FLAG_LEN=0, OUT_WIDTH=4)
//   out8:      Poseidon1Cols16<T,  8, 1>  (FLAG_LEN=1, OUT_WIDTH=8)

#[repr(C)]
#[derive(Debug)]
pub struct Poseidon1Cols16<T, const OUT_WIDTH: usize, const FLAG_LEN: usize> {
    pub multiplicity: T,
    pub nu_b: T,
    pub nu_c: T,
    pub flag_left: T,
    pub offset_left: T,
    pub addr_left_lo: T,
    pub addr_left_hi: T,
    /// Present only for out8 (FLAG_LEN=1); ZST ([T;0]) for permute16 and out4.
    pub flag_permute: [T; FLAG_LEN],
    pub inputs: [T; WIDTH],
    pub beginning_full_rounds: [[T; WIDTH]; HALF_INITIAL_FULL_ROUNDS],
    pub partial_rounds: [T; PARTIAL_ROUNDS],
    pub ending_full_rounds: [[T; WIDTH]; HALF_FINAL_FULL_ROUNDS - 1],
    /// Output cells: subsumes old out_lo + out_hi.
    /// permute16: out[0..8]=old out_lo, out[8..16]=old out_hi.
    pub out: [T; OUT_WIDTH],
}

/// Number of committed columns for a given `(OUT_WIDTH, FLAG_LEN)` monomorphization.
pub const fn num_cols<const OUT_WIDTH: usize, const FLAG_LEN: usize>() -> usize {
    size_of::<Poseidon1Cols16<u8, OUT_WIDTH, FLAG_LEN>>()
}

/// Total column count (committed + 2 virtual: NU_A and DOMAINSEP).
pub const fn num_cols_total<const OUT_WIDTH: usize, const FLAG_LEN: usize>() -> usize {
    num_cols::<OUT_WIDTH, FLAG_LEN>() + 2
}

// ============================================================================
// Per-table column-index constants
// ============================================================================
//
// Shared prefix (cols 0-6, same for all three tables):
pub const POSEIDON_COL_MULTIPLICITY: ColIndex = 0;
pub const POSEIDON_COL_NU_B: ColIndex = 1;
pub const POSEIDON_COL_NU_C: ColIndex = 2;
pub const POSEIDON_COL_FLAG_LEFT: ColIndex = 3;
pub const POSEIDON_COL_OFFSET_LEFT: ColIndex = 4;
pub const POSEIDON_COL_ADDR_LEFT_LO: ColIndex = 5;
pub const POSEIDON_COL_ADDR_LEFT_HI: ColIndex = 6;
// permute16 / out4 (FLAG_LEN=0): INPUT_START at col 7
pub const POSEIDON_COL_INPUT_START: ColIndex = 7;
/// Output base for permute16 (OUT_WIDTH=16, FLAG_LEN=0):
pub const POSEIDON_COL_OUT_LO: ColIndex = num_cols::<16, 0>() - 16;
pub const POSEIDON_COL_OUT_HI: ColIndex = num_cols::<16, 0>() - 8;
/// Virtual (non-committed) columns for permute16:
pub const POSEIDON_COL_NU_A: ColIndex = num_cols::<16, 0>();
pub const POSEIDON_COL_DOMAINSEP: ColIndex = num_cols::<16, 0>() + 1;

// out4-specific column indices (FLAG_LEN=0, OUT_WIDTH=4):
pub const POSEIDON_OUT4_COL_MULTIPLICITY: ColIndex = 0;
pub const POSEIDON_OUT4_COL_NU_B: ColIndex = 1;
pub const POSEIDON_OUT4_COL_NU_C: ColIndex = 2;
pub const POSEIDON_OUT4_COL_FLAG_LEFT: ColIndex = 3;
pub const POSEIDON_OUT4_COL_OFFSET_LEFT: ColIndex = 4;
pub const POSEIDON_OUT4_COL_ADDR_LEFT_LO: ColIndex = 5;
pub const POSEIDON_OUT4_COL_ADDR_LEFT_HI: ColIndex = 6;
pub const POSEIDON_OUT4_COL_INPUT_START: ColIndex = 7;
pub const POSEIDON_OUT4_COL_OUT_LO: ColIndex = num_cols::<4, 0>() - HALF_DIGEST_LEN;
pub const POSEIDON_OUT4_COL_NU_A: ColIndex = num_cols::<4, 0>();
pub const POSEIDON_OUT4_COL_DOMAINSEP: ColIndex = num_cols::<4, 0>() + 1;

// out8-specific column indices (FLAG_LEN=1, OUT_WIDTH=8):
pub const POSEIDON_OUT8_COL_MULTIPLICITY: ColIndex = 0;
pub const POSEIDON_OUT8_COL_NU_B: ColIndex = 1;
pub const POSEIDON_OUT8_COL_NU_C: ColIndex = 2;
pub const POSEIDON_OUT8_COL_FLAG_LEFT: ColIndex = 3;
pub const POSEIDON_OUT8_COL_OFFSET_LEFT: ColIndex = 4;
pub const POSEIDON_OUT8_COL_ADDR_LEFT_LO: ColIndex = 5;
pub const POSEIDON_OUT8_COL_ADDR_LEFT_HI: ColIndex = 6;
pub const POSEIDON_OUT8_COL_FLAG_PERMUTE: ColIndex = 7;
pub const POSEIDON_OUT8_COL_INPUT_START: ColIndex = 8;
pub const POSEIDON_OUT8_COL_OUT_LO: ColIndex = num_cols::<8, 1>() - DIGEST_LEN;
pub const POSEIDON_OUT8_COL_NU_A: ColIndex = num_cols::<8, 1>();
pub const POSEIDON_OUT8_COL_DOMAINSEP: ColIndex = num_cols::<8, 1>() + 1;

// Legacy function aliases (backward-compat with call sites).
pub const fn num_cols_poseidon_16() -> usize { num_cols::<16, 0>() }
pub const fn num_cols_total_poseidon_16() -> usize { num_cols_total::<16, 0>() }
pub const fn num_cols_poseidon_16_out4() -> usize { num_cols::<4, 0>() }
pub const fn num_cols_total_poseidon_16_out4() -> usize { num_cols_total::<4, 0>() }
pub const fn num_cols_poseidon_16_out8() -> usize { num_cols::<8, 1>() }
pub const fn num_cols_total_poseidon_16_out8() -> usize { num_cols_total::<8, 1>() }

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

// ============================================================================
// One const-generic Poseidon16 table
// ============================================================================
//
// Three live monomorphizations:
//   Poseidon16Precompile<16, 0, FF_OFF,   BUS>  →  permute16
//   Poseidon16Precompile<4,  0, FF_ON,    BUS>  →  out4 (compress_quarter)
//   Poseidon16Precompile<8,  1, FF_GATED, BUS>  →  out8 (compress_half + permute_half)
//
// `FLAG_LEN` is 0 or 1 — matches the Poseidon1Cols16 FLAG_LEN param directly.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poseidon16Precompile<
    const OUT_WIDTH: usize,
    const FLAG_LEN: usize,
    const FEEDFORWARD: u8,
    const BUS: bool,
>;

impl<const OUT_WIDTH: usize, const FLAG_LEN: usize, const FEEDFORWARD: u8, const BUS: bool>
    TableT for Poseidon16Precompile<OUT_WIDTH, FLAG_LEN, FEEDFORWARD, BUS>
{
    fn name(&self) -> &'static str {
        match OUT_WIDTH {
            16 => "poseidon16",
            4  => "poseidon16_out4",
            8  => "poseidon16_out8",
            _  => unreachable!("unsupported OUT_WIDTH"),
        }
    }

    fn table(&self) -> Table {
        match OUT_WIDTH {
            16 => Table::poseidon16(),
            4  => Table::poseidon16_out4(),
            8  => Table::poseidon16_out8(),
            _  => unreachable!("unsupported OUT_WIDTH"),
        }
    }

    fn n_columns_total(&self) -> usize {
        num_cols_total::<OUT_WIDTH, FLAG_LEN>()
    }

    fn bus_interactions(&self) -> Vec<BusInteraction> {
        // input_start = 7 (FLAG_LEN=0) or 8 (FLAG_LEN=1)
        let input_start: ColIndex = POSEIDON_COL_ADDR_LEFT_HI + 1 + FLAG_LEN;
        let out_col: ColIndex = num_cols::<OUT_WIDTH, FLAG_LEN>() - OUT_WIDTH;
        let nu_a_col: ColIndex = num_cols::<OUT_WIDTH, FLAG_LEN>();
        let domainsep_col: ColIndex = num_cols::<OUT_WIDTH, FLAG_LEN>() + 1;

        let mut buses = vec![BusInteraction {
            direction: BusDirection::Pull,
            multiplicity: BusMultiplicity::Column(POSEIDON_COL_MULTIPLICITY),
            domainsep: BusData::Column(domainsep_col),
            data: vec![
                BusData::Column(nu_a_col),
                BusData::Column(POSEIDON_COL_NU_B),
                BusData::Column(POSEIDON_COL_NU_C),
            ],
        }];
        // left-lo: HALF_DIGEST_LEN cells
        buses.extend(memory_lookups_consecutive(
            POSEIDON_COL_ADDR_LEFT_LO,
            input_start,
            HALF_DIGEST_LEN,
        ));
        // left-hi: HALF_DIGEST_LEN cells
        buses.extend(memory_lookups_consecutive(
            POSEIDON_COL_ADDR_LEFT_HI,
            input_start + HALF_DIGEST_LEN,
            HALF_DIGEST_LEN,
        ));
        // right: DIGEST_LEN cells
        buses.extend(memory_lookups_consecutive(
            POSEIDON_COL_NU_B,
            input_start + DIGEST_LEN,
            DIGEST_LEN,
        ));
        // result: OUT_WIDTH cells
        buses.extend(memory_lookups_consecutive(
            POSEIDON_COL_NU_C,
            out_col,
            OUT_WIDTH,
        ));
        buses
    }

    fn padding_row(&self, zero_vec_ptr: usize, null_hash_ptr: usize, null_permute_ptr: usize, _ending_pc: usize) -> Vec<F> {
        let n_total = num_cols_total::<OUT_WIDTH, FLAG_LEN>();
        let n_committed = num_cols::<OUT_WIDTH, FLAG_LEN>();
        let _input_start: ColIndex = POSEIDON_COL_ADDR_LEFT_HI + 1 + FLAG_LEN;
        let nu_a_col: ColIndex = n_committed;
        let domainsep_col: ColIndex = n_committed + 1;

        let mut row = vec![F::ZERO; n_total];

        // Set shared prefix fields directly by index.
        row[POSEIDON_COL_MULTIPLICITY] = F::ZERO;
        row[POSEIDON_COL_NU_B] = F::from_usize(zero_vec_ptr);
        // permute16 reads all 16 output cells from null_permute_ptr;
        // out4/out8 read their shorter result from null_hash_ptr.
        row[POSEIDON_COL_NU_C] = if FEEDFORWARD == FF_OFF {
            F::from_usize(null_permute_ptr)
        } else {
            F::from_usize(null_hash_ptr)
        };
        row[POSEIDON_COL_FLAG_LEFT] = F::ZERO;
        row[POSEIDON_COL_OFFSET_LEFT] = F::ZERO;
        row[POSEIDON_COL_ADDR_LEFT_LO] = F::from_usize(zero_vec_ptr);
        row[POSEIDON_COL_ADDR_LEFT_HI] = F::from_usize(zero_vec_ptr + HALF_DIGEST_LEN);
        // flag_permute (col 7, present only when FLAG_LEN=1):
        if FLAG_LEN == 1 {
            row[POSEIDON_OUT8_COL_FLAG_PERMUTE] = F::ZERO;
        }
        // inputs: already zeroed

        // Virtual columns
        row[nu_a_col] = F::from_usize(zero_vec_ptr);
        // Domainsep for the padding row: flag_left=0, flag_permute=0 (or absent):
        //   permute16: BASE + FLAG_PERMUTE_SHIFT (permute always true)
        //   out4:      BASE
        //   out8:      BASE (flag_permute=0 → compress sub-mode)
        let domainsep = match FEEDFORWARD {
            FF_OFF   => POSEIDON_DOMAINSEP_BASE + POSEIDON_FLAG_PERMUTE_SHIFT,
            FF_ON    => POSEIDON_DOMAINSEP_BASE,
            FF_GATED => POSEIDON_DOMAINSEP_BASE,
            _        => unreachable!(),
        };
        row[domainsep_col] = F::from_usize(domainsep);

        // Fill the round columns by calling the generic trace generator.
        // Use raw-pointer cast to the correct Cols type.
        let mut ptrs: Vec<*mut F> = (0..n_committed)
            .map(|i| unsafe { row.as_mut_ptr().add(i) })
            .collect();
        let perm: &mut Poseidon1Cols16<&mut F, OUT_WIDTH, FLAG_LEN> =
            unsafe { &mut *(ptrs.as_mut_ptr() as *mut Poseidon1Cols16<&mut F, OUT_WIDTH, FLAG_LEN>) };
        trace_gen::generate_trace_rows_for_perm::<F, OUT_WIDTH, FLAG_LEN>(perm);

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

        // Mode guards (mirror old per-table debug_asserts)
        match FEEDFORWARD {
            FF_OFF => debug_assert!(
                !half_output && permute,
                "non-permute16 mode leaked into base poseidon table (half_output={half_output}, permute={permute})"
            ),
            FF_ON => debug_assert!(
                half_output && !permute,
                "out4 table received non-out4 mode (half_output={half_output}, permute={permute})"
            ),
            FF_GATED => debug_assert!(
                half_output == permute,
                "out8 table got non-out8 mode (half_output={half_output}, permute={permute})"
            ),
            _ => unreachable!(),
        }

        let trace = ctx.traces.get_mut(&self.table()).unwrap();
        let input_start: ColIndex = POSEIDON_COL_ADDR_LEFT_HI + 1 + FLAG_LEN;
        let nu_a_col: ColIndex = num_cols::<OUT_WIDTH, FLAG_LEN>();
        let domainsep_col: ColIndex = num_cols::<OUT_WIDTH, FLAG_LEN>() + 1;

        let arg_a_usize = arg_a.to_usize();
        let flag_hardcoded = hardcoded_offset_left.is_some();
        let left_first_addr = hardcoded_offset_left.unwrap_or(arg_a_usize);
        let left_second_addr = if flag_hardcoded {
            arg_a_usize
        } else {
            arg_a_usize + HALF_DIGEST_LEN
        };
        let mut input = [F::ZERO; DIGEST_LEN * 2];
        ctx.memory.get_slice_into(left_first_addr, &mut input[..HALF_DIGEST_LEN])?;
        ctx.memory.get_slice_into(left_second_addr, &mut input[HALF_DIGEST_LEN..DIGEST_LEN])?;
        ctx.memory.get_slice_into(arg_b.to_usize(), &mut input[DIGEST_LEN..])?;

        let res_addr = index_res_a.to_usize();
        match FEEDFORWARD {
            FF_OFF => {
                // permute16: always permutation, write all 16 cells
                let permuted = poseidon16_permute(input);
                ctx.memory.set_slice(res_addr, &permuted)?;
            }
            FF_ON => {
                // out4: always compression, write first OUT_WIDTH cells
                let output = poseidon16_compress(input);
                ctx.memory.set_slice(res_addr, &output[..OUT_WIDTH])?;
            }
            FF_GATED => {
                // out8: branch on runtime flag
                if permute {
                    let permuted = poseidon16_permute(input);
                    ctx.memory.set_slice(res_addr, &permuted[..OUT_WIDTH])?;
                } else {
                    let output = poseidon16_compress(input);
                    ctx.memory.set_slice(res_addr, &output[..OUT_WIDTH])?;
                }
            }
            _ => unreachable!(),
        }

        let hardcoded_offset_left_val = hardcoded_offset_left.unwrap_or(0);

        // Committed columns (shared prefix)
        trace.columns[POSEIDON_COL_MULTIPLICITY].push(F::ONE);
        trace.columns[POSEIDON_COL_NU_B].push(arg_b);
        trace.columns[POSEIDON_COL_NU_C].push(index_res_a);
        trace.columns[POSEIDON_COL_FLAG_LEFT].push(F::from_bool(flag_hardcoded));
        trace.columns[POSEIDON_COL_OFFSET_LEFT].push(F::from_usize(hardcoded_offset_left_val));
        trace.columns[POSEIDON_COL_ADDR_LEFT_LO].push(F::from_usize(left_first_addr));
        trace.columns[POSEIDON_COL_ADDR_LEFT_HI].push(F::from_usize(left_second_addr));
        // flag_permute column (out8 only, FLAG_LEN=1)
        if FLAG_LEN == 1 {
            trace.columns[POSEIDON_OUT8_COL_FLAG_PERMUTE].push(F::from_bool(permute));
        }
        for (i, value) in input.iter().enumerate() {
            trace.columns[input_start + i].push(*value);
        }

        // Non-committed columns
        trace.columns[nu_a_col].push(arg_a);
        // Domainsep must match eval() reconstruction exactly:
        //   permute16: BASE + FLAG_PERMUTE_SHIFT (always permute) + flag_left terms
        //   out4:      BASE + flag_left terms
        //   out8:      BASE + flag_permute*FLAG_PERMUTE_SHIFT + flag_left terms
        let domainsep = POSEIDON_DOMAINSEP_BASE
            + match FEEDFORWARD {
                FF_OFF   => POSEIDON_FLAG_PERMUTE_SHIFT,
                FF_ON    => 0,
                FF_GATED => POSEIDON_FLAG_PERMUTE_SHIFT * (permute as usize),
                _        => unreachable!(),
            }
            + POSEIDON_FLAG_LEFT_SHIFT * (flag_hardcoded as usize)
            + POSEIDON_OFFSET_LEFT_SHIFT * hardcoded_offset_left_val;
        trace.columns[domainsep_col].push(F::from_usize(domainsep));

        Ok(())
    }
}

impl<const OUT_WIDTH: usize, const FLAG_LEN: usize, const FEEDFORWARD: u8, const BUS: bool>
    Air for Poseidon16Precompile<OUT_WIDTH, FLAG_LEN, FEEDFORWARD, BUS>
{
    type ExtraData = ExtraDataForBuses<EF>;

    fn n_columns(&self) -> usize {
        num_cols::<OUT_WIDTH, FLAG_LEN>()
    }

    fn degree_air(&self) -> usize {
        9
    }

    fn low_degree_air(&self) -> Option<(usize, usize)> {
        Some((3, PARTIAL_ROUNDS))
    }

    fn n_shift_columns(&self) -> usize {
        0
    }

    fn n_constraints(&self) -> usize {
        // Breakdown (verified by test_n_constraints_*):
        //   2*BUS        — bus virtual constraints (0 when BUS=false)
        //   2            — assert_bool(multiplicity) + assert_bool(flag_left)
        //   FLAG_LEN     — assert_bool(flag_permute) for out8 (FLAG_LEN=1); 0 otherwise
        //   2            — two addr assertions (flag_left*(offset_left - addr_left_lo),
        //                  one_minus_flag_left*(nu_a - addr_left_lo))
        //   (HALF_INITIAL_FULL_ROUNDS + HALF_FINAL_FULL_ROUNDS - 1) * WIDTH
        //                — intermediate full-round constraints (eval_2_full_rounds emits WIDTH each)
        //   PARTIAL_ROUNDS — one assert_eq_low per partial round
        //   OUT_WIDTH    — output constraints from eval_last_2_full_rounds_generic
        //
        // Verification:
        //   permute16 (OUT_WIDTH=16, FLAG_LEN=0, FF_OFF): 0+2+0+2+(2+2-1)*16+14+16 = 4+48+14+16 = 82? → no
        //   Let me re-count with the actual round constants:
        //   HALF_INITIAL_FULL_ROUNDS = POSEIDON1_HALF_FULL_ROUNDS/2 / 2
        //   HALF_FINAL_FULL_ROUNDS   = POSEIDON1_HALF_FULL_ROUNDS/2 / 2
        //   Need the actual values to verify. Tests are the guardrail.
        2 * BUS as usize
            + 2        // assert_bool(multiplicity) + assert_bool(flag_left)
            + FLAG_LEN // assert_bool(flag_permute) only for FLAG_LEN=1
            + 2        // two addr assertions
            + (HALF_INITIAL_FULL_ROUNDS + HALF_FINAL_FULL_ROUNDS - 1) * WIDTH
            + PARTIAL_ROUNDS
            + OUT_WIDTH
    }

    fn eval<AB: AirBuilder>(&self, builder: &mut AB, extra_data: &Self::ExtraData) {
        let cols: Poseidon1Cols16<AB::IF, OUT_WIDTH, FLAG_LEN> = {
            let flat = builder.flat();
            let (prefix, shorts, suffix) =
                unsafe { flat.align_to::<Poseidon1Cols16<AB::IF, OUT_WIDTH, FLAG_LEN>>() };
            debug_assert!(prefix.is_empty(), "Alignment should match");
            debug_assert!(suffix.is_empty(), "Alignment should match");
            debug_assert_eq!(shorts.len(), 1);
            unsafe { std::ptr::read(&shorts[0]) }
        };

        // flag_permute: present only for FLAG_LEN=1 (out8).
        // For FLAG_LEN=0: zero-size array → no runtime flag; use compile-time 0.
        let flag_permute_val: AB::IF = if FLAG_LEN == 1 {
            cols.flag_permute[0]
        } else {
            AB::IF::ZERO
        };

        // Domainsep reconstruction (must match execute() push exactly):
        //   permute16: BASE + FLAG_PERMUTE_SHIFT + flag_left terms  (permute always true)
        //   out4:      BASE + flag_left terms
        //   out8:      BASE + flag_permute*FLAG_PERMUTE_SHIFT + flag_left terms
        let domainsep_reconstructed = AB::IF::from_usize(POSEIDON_DOMAINSEP_BASE)
            + match FEEDFORWARD {
                FF_OFF   => AB::IF::from_usize(POSEIDON_FLAG_PERMUTE_SHIFT),
                FF_ON    => AB::IF::ZERO,
                FF_GATED => flag_permute_val * AB::F::from_usize(POSEIDON_FLAG_PERMUTE_SHIFT),
                _        => unreachable!(),
            }
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
        if FLAG_LEN == 1 {
            builder.assert_bool(cols.flag_permute[0]);
        }

        builder.assert_zero(cols.flag_left * (cols.offset_left - cols.addr_left_lo));
        builder.assert_zero(one_minus_flag_left * (nu_a - cols.addr_left_lo));

        eval_poseidon_generic::<AB, OUT_WIDTH, FLAG_LEN, FEEDFORWARD>(builder, &cols);
    }
}

// ============================================================================
// Generic permutation circuit
// ============================================================================

fn eval_poseidon_generic<
    AB: AirBuilder,
    const OUT_WIDTH: usize,
    const FLAG_LEN: usize,
    const FEEDFORWARD: u8,
>(
    builder: &mut AB,
    local: &Poseidon1Cols16<AB::IF, OUT_WIDTH, FLAG_LEN>,
) {
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

    let flag_permute_val: AB::IF = if FLAG_LEN == 1 {
        local.flag_permute[0]
    } else {
        AB::IF::ZERO
    };

    eval_last_2_full_rounds_generic::<AB, OUT_WIDTH, FEEDFORWARD>(
        &local.inputs,
        &mut state,
        &local.out,
        flag_permute_val,
        &final_constants[2 * (HALF_FINAL_FULL_ROUNDS - 1)],
        &final_constants[2 * (HALF_FINAL_FULL_ROUNDS - 1) + 1],
        builder,
    );
}

/// Final 2 full rounds: unified across all three modes.
///
/// - `FF_OFF`   (permute16): no feedforward, constrain `out[i] = state[i]` for i in 0..OUT_WIDTH.
///   For permute16 OUT_WIDTH=16: i<8 = old out_lo, i>=8 = old out_hi — same order as old code.
/// - `FF_ON`    (out4):      feedforward always active: `out[i] = state[i] + initial[i]`.
/// - `FF_GATED` (out8):      feedforward coeff = `(1 - flag_permute)`:
///   `out[i] = state[i] + (1-flag_permute)*initial[i]`.
///
/// Single `for i in 0..OUT_WIDTH` loop preserves emission order (lo-then-hi for permute16).
#[inline]
fn eval_last_2_full_rounds_generic<
    AB: AirBuilder,
    const OUT_WIDTH: usize,
    const FEEDFORWARD: u8,
>(
    initial_state: &[AB::IF; WIDTH],
    state: &mut [AB::IF; WIDTH],
    out: &[AB::IF; OUT_WIDTH],
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

    match FEEDFORWARD {
        FF_OFF => {
            // Pure permutation: no feedforward. Constrain all OUT_WIDTH cells.
            // For permute16 (OUT_WIDTH=16): i<8 maps to old out_lo, i>=8 to old out_hi.
            for i in 0..OUT_WIDTH {
                builder.assert_zero(state[i] - out[i]);
            }
        }
        FF_ON => {
            // Compression: feedforward always active.
            for i in 0..OUT_WIDTH {
                builder.assert_zero(state[i] + initial_state[i] - out[i]);
            }
        }
        FF_GATED => {
            // Feedforward gated by (1 - flag_permute).
            let feedforward = AB::IF::ONE - flag_permute;
            for i in 0..OUT_WIDTH {
                builder.assert_zero(state[i] + feedforward * initial_state[i] - out[i]);
            }
        }
        _ => unreachable!(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use backend::get_symbolic_constraints_and_bus_data_values;

    /// Verify that `n_constraints()` exactly matches the actual number of constraints produced
    /// by `eval()`, as counted symbolically.  This test must pass for the proof system to work.
    #[test]
    fn test_n_constraints_base_permute16() {
        let air = Poseidon16Precompile::<16, 0, FF_OFF, false>;
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
        let air = Poseidon16Precompile::<4, 0, FF_ON, false>;
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
        let air = Poseidon16Precompile::<8, 1, FF_GATED, false>;
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
            size_of::<Poseidon1Cols16<u8, 8, 1>>(),
            "num_cols_poseidon_16_out8() must equal size_of::<Poseidon1Cols16<u8, 8, 1>>()"
        );
    }

    /// Spike: assert that the generic struct sizes match the old per-table num_cols functions.
    #[test]
    fn test_generic_cols_size_invariant() {
        // permute16: FLAG_LEN=0, OUT_WIDTH=16
        let generic_16 = size_of::<Poseidon1Cols16<u8, 16, 0>>();
        assert_eq!(generic_16, num_cols_poseidon_16(),
            "permute16: generic size ({}) != num_cols_poseidon_16() ({})", generic_16, num_cols_poseidon_16());

        // out4: FLAG_LEN=0, OUT_WIDTH=4
        let generic_4 = size_of::<Poseidon1Cols16<u8, 4, 0>>();
        assert_eq!(generic_4, num_cols_poseidon_16_out4(),
            "out4: generic size ({}) != num_cols_poseidon_16_out4() ({})", generic_4, num_cols_poseidon_16_out4());

        // out8: FLAG_LEN=1, OUT_WIDTH=8
        let generic_8 = size_of::<Poseidon1Cols16<u8, 8, 1>>();
        assert_eq!(generic_8, num_cols_poseidon_16_out8(),
            "out8: generic size ({}) != num_cols_poseidon_16_out8() ({})", generic_8, num_cols_poseidon_16_out8());
    }
}
