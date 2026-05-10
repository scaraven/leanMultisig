#![cfg_attr(not(test), allow(unused_crate_dependencies))]
<<<<<<< HEAD
use backend::*;
use lean_prover::SNARK_DOMAIN_SEP;
use lean_prover::prove_execution::prove_execution;
use lean_prover::verify_execution::ProofVerificationDetails;
use lean_prover::verify_execution::verify_execution;
use lean_vm::*;
use tracing::instrument;
use utils::{build_prover_state, get_poseidon16, poseidon_compress_slice, poseidon16_compress_pair};
use xmss::{LOG_LIFETIME, MESSAGE_LEN_FE, SIG_SIZE_FE, XmssPublicKey, XmssSignature, slot_to_field_elements};

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::compilation::bytecode_reduction_sumcheck_proof_size;
pub use crate::compilation::{
    get_aggregation_bytecode, get_sphincs_bytecode, init_aggregation_bytecode, init_sphincs_bytecode,
};

=======
>>>>>>> d13cfa5d23c2edbd907afca9b598c1622f03fcbc
pub mod benchmark;
mod bytecode_claims;
mod compilation;
<<<<<<< HEAD
pub mod sphincs;
=======
mod type_1_aggregation;
mod type_2_aggregation;
>>>>>>> d13cfa5d23c2edbd907afca9b598c1622f03fcbc

use backend::{Evaluation, Proof, ProofError, RawProof};
pub use compilation::{
    MAX_RECURSIONS, MAX_XMSS_AGGREGATED, MAX_XMSS_DUPLICATES, NUM_REPEATED_ONES, PREAMBLE_MEMORY_LEN, ZERO_VEC_LEN,
    get_aggregation_bytecode, init_aggregation_bytecode,
};
use lean_prover::verify_execution::verify_execution;
use lean_vm::{DIGEST_LEN, EF, F};
pub use type_1_aggregation::{TypeOneInfo, TypeOneMultiSignature, aggregate_type_1, verify_type_1};
pub use type_2_aggregation::{TypeTwoMultiSignature, merge_many_type_1, split_type_2, verify_type_2};
use utils::poseidon_compress_slice;

#[allow(missing_debug_implementations)]
pub struct InnerVerified {
    pub input_data: Vec<F>,
    pub input_data_hash: [F; DIGEST_LEN],
    pub bytecode_evaluation: Evaluation<EF>,
    pub raw_proof: RawProof<F>,
}

pub(crate) fn verify_inner(input_data: Vec<F>, proof: Proof<F>) -> Result<InnerVerified, ProofError> {
    let input_data_hash = poseidon_compress_slice(&input_data, true);
    let bytecode = get_aggregation_bytecode();
    let (verif, raw_proof) = verify_execution(bytecode, &input_data_hash, proof)?;
    Ok(InnerVerified {
        input_data,
        input_data_hash,
        bytecode_evaluation: verif.bytecode_evaluation,
        raw_proof,
    })
}
