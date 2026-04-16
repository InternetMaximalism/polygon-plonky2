/// WHIR-based multilinear polynomial commitment scheme.
///
/// Integrates the `whir` crate (arkworks-based) with the plonky2_mle
/// proving system via the `MultilinearPCS` trait.
///
/// Field conversion: plonky2's GoldilocksField (u64 repr) ↔ arkworks
/// Field64 (Montgomery repr) via canonical u64 serialization.
use std::borrow::Cow;

use ark_ff::PrimeField as ArkPrimeField;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, PrimeField64};
use whir::algebra::embedding::Basefield;
use whir::algebra::fields::{Field64 as ArkGoldilocks, Field64_3};
use whir::algebra::linear_form::{Evaluate, LinearForm, MultilinearExtension};
use whir::parameters::ProtocolParameters;
use whir::protocols::whir::{Config as WhirConfig, SplitWitness, Witness as WhirWitness};
use whir::transcript::codecs::Empty;
#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use whir::transcript::{DomainSeparator, Proof as WhirProofData, ProverState, VerifierState};

use crate::dense_mle::DenseMultilinearExtension;

/// WHIR session name used for domain separation in Fiat-Shamir (legacy/default).
pub const WHIR_SESSION_NAME: &str = "plonky2-mle-whir";
/// WHIR session name for the split-commit mode (preprocessed + witness in one proof).
/// SECURITY: Must differ from legacy session names to prevent cross-protocol confusion.
pub const WHIR_SESSION_SPLIT: &str = "plonky2-mle-whir-split";
/// WHIR session name for the auxiliary commitment (C̃ + h̃ oracle polynomials).
/// SECURITY: Must differ from all other session names to prevent cross-protocol confusion.
pub const WHIR_SESSION_AUX: &str = "plonky2-mle-whir-aux";

// ═══════════════════════════════════════════════════════════════════════════
//  Field conversion
// ═══════════════════════════════════════════════════════════════════════════

/// Convert a plonky2 GoldilocksField element to arkworks Field64.
pub fn plonky2_to_ark(val: GoldilocksField) -> ArkGoldilocks {
    ArkGoldilocks::from(val.to_canonical_u64())
}

/// Convert an arkworks Field64 element to plonky2 GoldilocksField.
pub fn ark_to_plonky2(val: ArkGoldilocks) -> GoldilocksField {
    let repr: u64 = val.into_bigint().0[0];
    GoldilocksField::from_canonical_u64(repr)
}

/// Convert a vector of plonky2 field elements to arkworks.
pub fn plonky2_vec_to_ark(vals: &[GoldilocksField]) -> Vec<ArkGoldilocks> {
    vals.iter().map(|v| plonky2_to_ark(*v)).collect()
}

/// Convert a vector of arkworks field elements to plonky2.
pub fn ark_vec_to_plonky2(vals: &[ArkGoldilocks]) -> Vec<GoldilocksField> {
    vals.iter().map(|v| ark_to_plonky2(*v)).collect()
}

// ═══════════════════════════════════════════════════════════════════════════
//  WHIR PCS wrapper
// ═══════════════════════════════════════════════════════════════════════════

/// WHIR polynomial commitment scheme operating over GoldilocksField.
///
/// Uses `Basefield<Field64_3>` embedding: polynomial data lives in the 64-bit
/// base field, challenges use the 192-bit cubic extension for security.
/// The WHIR config is parameterised by rate, security level, and folding factor.
pub struct WhirPCS {
    pub params: ProtocolParameters,
}

/// Commitment: the serialized WHIR proof (for the verifier).
#[derive(Clone, Debug)]
pub struct WhirCommitment {
    /// Serialized WHIR proof bytes.
    pub proof_bytes: Vec<u8>,
}

/// Commit state: data the prover retains for the opening phase.
/// (Unused in the current two-phase API; kept for backward compat.)
#[derive(Clone)]
pub struct WhirCommitState {
    /// The original polynomial evaluations in arkworks representation.
    pub ark_evals: Vec<ArkGoldilocks>,
}

/// WHIR evaluation proof: the serialized interactive proof.
#[derive(Clone, Debug)]
pub struct WhirEvalProof {
    /// Serialized WHIR proof bytes (narg_string + hints).
    pub narg_string: Vec<u8>,
    pub hints: Vec<u8>,
    /// Transcript interaction pattern (debug mode only).
    /// Required for WHIR verifier transcript validation in debug builds.
    #[cfg(debug_assertions)]
    pub pattern: Vec<Interaction>,
}

/// Intermediate state for phased split-commit proving flow.
///
/// Supports adding vectors in phases: commit some vectors, derive external
/// challenges from their roots, then commit additional vectors before proving.
///
/// SECURITY: The WHIR internal transcript is advanced by each commit_single call.
/// External operations between commits do NOT affect the WHIR transcript.
/// The prove step computes cross-term OOD evaluations across ALL vectors.
pub struct WhirSplitCommitData {
    /// WHIR config for this polynomial size.
    pub config: WhirConfig<Basefield<Field64_3>>,
    /// Prover state (WHIR-internal transcript).
    pub prover_state: ProverState,
    /// Per-vector witnesses collected from commit_single calls.
    pub witnesses: Vec<WhirWitness<Field64_3, Basefield<Field64_3>>>,
    /// Per-vector polynomial evaluations in arkworks representation.
    pub ark_evals_list: Vec<Vec<ArkGoldilocks>>,
    /// Per-vector Merkle root hashes (32 bytes each).
    pub roots: Vec<Vec<u8>>,
    /// Number of variables (log2 of polynomial size).
    pub num_vars: usize,
}

impl WhirPCS {
    /// Create a WHIR PCS with the given parameters.
    /// rate = 1/2^starting_log_inv_rate (e.g., 4 for rate 1/16).
    pub fn new(
        security_level: usize,
        pow_bits: usize,
        starting_log_inv_rate: usize,
        folding_factor: usize,
    ) -> Self {
        let params = ProtocolParameters {
            security_level,
            pow_bits,
            initial_folding_factor: folding_factor,
            folding_factor,
            unique_decoding: false,
            starting_log_inv_rate,
            batch_size: 1,
            hash_id: whir::hash::KECCAK,
        };
        Self { params }
    }

    /// Default: rate 1/16, 90-bit security, 0 PoW bits, folding factor 4.
    pub fn default_rate_16() -> Self {
        Self::new(90, 0, 4, 4)
    }

    /// Create a WHIR PCS with parameters adapted for a given polynomial size.
    /// Ensures folding_factor <= num_vars and PoW bits within WHIR limits.
    pub fn for_num_vars(num_vars: usize) -> Self {
        let folding_factor = num_vars.clamp(1, 4);
        // Rate 1/16 (starting_log_inv_rate=4).
        // Must leave room for folding: num_vars > starting_log_inv_rate + folding
        let starting_log_inv_rate = if num_vars <= 4 {
            1
        } else {
            4.min(num_vars - folding_factor)
        };
        // PoW disabled; security level capped at 90 bits.
        let security_level = 90.min(num_vars * 5 + 10);
        let pow_bits = 0;
        Self::new(
            security_level,
            pow_bits,
            starting_log_inv_rate,
            folding_factor,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Split-commit API (unified proof for multiple vectors)
    // ═══════════════════════════════════════════════════════════════════════

    /// Compute the WHIR commitment root for a preprocessed polynomial.
    ///
    /// Uses WHIR_SESSION_SPLIT for domain separation to match the
    /// split-commit proving flow.
    ///
    /// SECURITY: The commitment root binds the prover to a specific polynomial.
    /// Changing any evaluation changes the Merkle root. The root is the first
    /// 32 bytes of the WHIR proof output, deterministic for a given polynomial
    /// + WHIR parameters + session name.
    pub fn commit_root(&self, poly: &DenseMultilinearExtension<GoldilocksField>) -> Vec<u8> {
        let num_vars = poly.num_vars;
        let size = 1 << num_vars;
        let ark_evals = plonky2_vec_to_ark(&poly.evaluations);

        let config = WhirConfig::<Basefield<Field64_3>>::new(size, &self.params);
        let ds = DomainSeparator::protocol(&config)
            .session(&WHIR_SESSION_SPLIT.to_string())
            .instance(&Empty);

        let mut prover_state = ProverState::new_std(&ds);
        // Commit a single vector to get its deterministic Merkle root.
        // The root is written as the first prover_message_hash in the transcript.
        let _witness = config.commit(&mut prover_state, &[&ark_evals]);
        let proof = prover_state.proof();
        proof.narg_string[..32.min(proof.narg_string.len())].to_vec()
    }

    /// Begin a phased split-commit by committing initial vectors.
    ///
    /// Each vector gets its own Merkle tree and root. The returned
    /// `WhirSplitCommitData` can be extended with `commit_additional`
    /// before calling `prove_split_with_eval`.
    ///
    /// SECURITY: The `session_name` creates domain separation.
    pub fn commit_split(
        &self,
        evals_list: &[&[ArkGoldilocks]],
        session_name: &str,
    ) -> WhirSplitCommitData {
        assert!(!evals_list.is_empty(), "Must provide at least one vector");
        let size = evals_list[0].len();
        let num_vars = size.trailing_zeros() as usize;
        assert!(size.is_power_of_two(), "Vector size must be a power of 2");
        for evals in evals_list {
            assert_eq!(evals.len(), size, "All vectors must have the same size");
        }

        let config = WhirConfig::<Basefield<Field64_3>>::new(size, &self.params);
        let ds = DomainSeparator::protocol(&config)
            .session(&session_name.to_string())
            .instance(&Empty);

        let mut prover_state = ProverState::new_std(&ds);

        // Use commit_single for each vector (phased approach).
        let mut witnesses = Vec::with_capacity(evals_list.len());
        let mut roots = Vec::with_capacity(evals_list.len());
        for evals in evals_list {
            let (witness, root) = config.commit_single(&mut prover_state, evals);
            roots.push(root.0.to_vec());
            witnesses.push(witness);
        }

        let ark_evals_list: Vec<Vec<ArkGoldilocks>> =
            evals_list.iter().map(|evals| evals.to_vec()).collect();

        WhirSplitCommitData {
            config,
            prover_state,
            witnesses,
            ark_evals_list,
            roots,
            num_vars,
        }
    }

    /// Add an additional vector to a phased split-commit session.
    ///
    /// Call this after deriving challenges from earlier commitment roots
    /// and computing challenge-dependent polynomials (e.g., C̃, h̃).
    ///
    /// SECURITY: The new vector is committed to the same WHIR transcript,
    /// ensuring cross-term OOD binding with all previous vectors.
    pub fn commit_additional(
        &self,
        commit_data: &mut WhirSplitCommitData,
        evals: &[ArkGoldilocks],
    ) -> Vec<u8> {
        let size = 1 << commit_data.num_vars;
        assert_eq!(evals.len(), size, "Additional vector size mismatch");

        let (witness, root) = commit_data
            .config
            .commit_single(&mut commit_data.prover_state, evals);
        let root_bytes = root.0.to_vec();
        commit_data.roots.push(root_bytes.clone());
        commit_data.witnesses.push(witness);
        commit_data.ark_evals_list.push(evals.to_vec());
        root_bytes
    }

    /// Generate a unified WHIR proof for split-committed vectors at one or more
    /// evaluation points.
    ///
    /// Each evaluation point becomes a separate `LinearForm` in the WHIR proof.
    /// Evaluations are returned per-point, per-vector (outer: points, inner: vectors).
    ///
    /// SECURITY: The evaluation values are computed internally using WHIR's
    /// embedding to ensure consistency with how WHIR verifies. Each evaluation
    /// point should be a sumcheck output point (e.g., constraint r, permutation
    /// r_perm) so that WHIR directly binds polynomial evaluations at the points
    /// where the verifier needs them.
    pub fn prove_split_with_eval(
        &self,
        mut commit_data: WhirSplitCommitData,
        eval_points: &[&[GoldilocksField]],
    ) -> (WhirEvalProof, Vec<Vec<Field64_3>>) {
        let num_vars = commit_data.num_vars;
        let num_vectors = commit_data.ark_evals_list.len();
        assert!(
            !eval_points.is_empty(),
            "SECURITY: At least one evaluation point is required"
        );
        for (i, pt) in eval_points.iter().enumerate() {
            assert_eq!(
                pt.len(),
                num_vars,
                "SECURITY: eval_points[{i}] length {} must match num_vars {num_vars}",
                pt.len()
            );
        }

        // Convert each evaluation point to Ext3 and build LinearForms.
        let points_ext3: Vec<Vec<Field64_3>> = eval_points
            .iter()
            .map(|pt| {
                pt.iter()
                    .map(|f| Field64_3::from(f.to_canonical_u64()))
                    .collect()
            })
            .collect();

        // Evaluate each vector at each point.
        // Layout: per_point_evals[point_idx] = [vec_0_eval, vec_1_eval, ...]
        let per_point_evals: Vec<Vec<Field64_3>> = points_ext3
            .iter()
            .map(|pt| {
                let lf = MultilinearExtension::new(pt.clone());
                commit_data
                    .ark_evals_list
                    .iter()
                    .map(|evals| lf.evaluate(commit_data.config.embedding(), evals))
                    .collect()
            })
            .collect();

        // Flatten evaluations: row-major (num_linear_forms × num_vectors).
        let evaluations: Vec<Field64_3> = per_point_evals.iter().flatten().copied().collect();
        assert_eq!(evaluations.len(), eval_points.len() * num_vectors);

        // Build LinearForms — one per evaluation point.
        let prove_lf: Vec<Box<dyn LinearForm<Field64_3>>> = points_ext3
            .into_iter()
            .map(|pt| Box::new(MultilinearExtension::new(pt)) as Box<dyn LinearForm<Field64_3>>)
            .collect();

        // Build vectors for prove_split.
        let vectors: Vec<Cow<'_, [ArkGoldilocks]>> = commit_data
            .ark_evals_list
            .iter()
            .map(|evals| Cow::Borrowed(evals.as_slice()))
            .collect();

        // Build SplitWitness from individually collected witnesses.
        let roots: Vec<whir::hash::Hash> = commit_data
            .roots
            .iter()
            .map(|r| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&r[..32]);
                whir::hash::Hash(arr)
            })
            .collect();
        let split_witness = SplitWitness::new(commit_data.witnesses, roots);

        let _final_claim = commit_data.config.prove_split(
            &mut commit_data.prover_state,
            vectors,
            split_witness,
            prove_lf,
            Cow::Owned(evaluations),
        );

        let proof = commit_data.prover_state.proof();

        let eval_proof = WhirEvalProof {
            narg_string: proof.narg_string,
            hints: proof.hints,
            #[cfg(debug_assertions)]
            pattern: proof.pattern,
        };

        (eval_proof, per_point_evals)
    }

    /// Verify a unified WHIR proof for split-committed vectors at one or more
    /// evaluation points.
    ///
    /// SECURITY: The session name must match the one used during proving.
    /// `eval_values` is flattened row-major: [point_0_vec_0, point_0_vec_1, ...,
    /// point_1_vec_0, point_1_vec_1, ...]. `num_vectors` is the number of
    /// committed vectors (typically 2: preprocessed + witness).
    pub fn verify_split(
        &self,
        num_vars: usize,
        proof: &WhirEvalProof,
        eval_values: &[Field64_3],
        session_name: &str,
        eval_points: &[&[GoldilocksField]],
        num_vectors: usize,
    ) -> Result<(), String> {
        assert!(
            !eval_points.is_empty(),
            "SECURITY: At least one evaluation point is required"
        );
        assert_eq!(
            eval_values.len(),
            eval_points.len() * num_vectors,
            "eval_values length {} must equal num_points({}) × num_vectors({})",
            eval_values.len(),
            eval_points.len(),
            num_vectors
        );
        for (i, pt) in eval_points.iter().enumerate() {
            assert_eq!(
                pt.len(),
                num_vars,
                "SECURITY: eval_points[{i}] length must match num_vars"
            );
        }

        let size = 1 << num_vars;

        let config = WhirConfig::<Basefield<Field64_3>>::new(size, &self.params);
        let ds = DomainSeparator::protocol(&config)
            .session(&session_name.to_string())
            .instance(&Empty);

        let proof_data = WhirProofData {
            narg_string: proof.narg_string.clone(),
            hints: proof.hints.clone(),
            #[cfg(debug_assertions)]
            pattern: proof.pattern.clone(),
        };

        let mut verifier_state = VerifierState::new_std(&ds, &proof_data);

        // Receive per-vector commitments (split mode).
        let commitments = config
            .receive_split_commitment(&mut verifier_state, num_vectors)
            .map_err(|e| format!("WHIR split commitment verification failed: {:?}", e))?;
        let commitment_refs: Vec<&_> = commitments.iter().collect();

        // Verify the combined proof.
        let final_claim = config
            .verify_split(&mut verifier_state, &commitment_refs, eval_values)
            .map_err(|e| format!("WHIR split verification failed: {:?}", e))?;

        // Build LinearForms — one per evaluation point.
        let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> = eval_points
            .iter()
            .map(|pt| {
                let ext3: Vec<Field64_3> = pt
                    .iter()
                    .map(|f| Field64_3::from(f.to_canonical_u64()))
                    .collect();
                Box::new(MultilinearExtension::new(ext3)) as Box<dyn LinearForm<Field64_3>>
            })
            .collect();

        final_claim
            .verify(
                verify_lf
                    .iter()
                    .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
            )
            .map_err(|e| format!("WHIR split evaluation verification failed: {:?}", e))?;

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Auxiliary single-vector API (commit + multi-point prove)
    // ═══════════════════════════════════════════════════════════════════════

    /// Commit and prove a single auxiliary polynomial at multiple evaluation points.
    ///
    /// Used for the auxiliary commitment round: after challenges are derived,
    /// the prover commits C̃ and h̃ (batched into one polynomial) and proves
    /// evaluation at both the constraint point r and the permutation point r_perm.
    ///
    /// Returns (commitment_root, proof, per_point_evals).
    ///
    /// SECURITY: Uses a dedicated session name to prevent cross-protocol confusion
    /// with the main split-commit WHIR proof. The auxiliary polynomial binds
    /// C̃(r) and h̃(r_perm) to the committed polynomial, closing the oracle gap.
    pub fn commit_and_prove_aux(
        &self,
        poly: &DenseMultilinearExtension<GoldilocksField>,
        eval_points: &[&[GoldilocksField]],
        session_name: &str,
    ) -> (Vec<u8>, WhirEvalProof, Vec<Field64_3>) {
        let num_vars = poly.num_vars;
        let size = 1 << num_vars;
        let ark_evals = plonky2_vec_to_ark(&poly.evaluations);

        assert!(
            !eval_points.is_empty(),
            "SECURITY: At least one evaluation point required"
        );
        for (i, pt) in eval_points.iter().enumerate() {
            assert_eq!(
                pt.len(),
                num_vars,
                "SECURITY: eval_points[{i}] length must match num_vars {num_vars}"
            );
        }

        let config = WhirConfig::<Basefield<Field64_3>>::new(size, &self.params);
        let ds = DomainSeparator::protocol(&config)
            .session(&session_name.to_string())
            .instance(&Empty);

        let mut prover_state = ProverState::new_std(&ds);
        let witness = config.commit(&mut prover_state, &[&ark_evals]);

        // Extract commitment root (first 32 bytes of transcript).
        let commit_proof = prover_state.proof();
        let root = commit_proof.narg_string[..32.min(commit_proof.narg_string.len())].to_vec();
        // Reset prover state — we need to re-create it because proof() consumes state.
        // Instead, re-do the commit to get fresh prover_state for proving.
        let mut prover_state = ProverState::new_std(&ds);
        let _witness = config.commit(&mut prover_state, &[&ark_evals]);

        // Build LinearForms and evaluate at each point.
        let points_ext3: Vec<Vec<Field64_3>> = eval_points
            .iter()
            .map(|pt| {
                pt.iter()
                    .map(|f| Field64_3::from(f.to_canonical_u64()))
                    .collect()
            })
            .collect();

        let per_point_evals: Vec<Field64_3> = points_ext3
            .iter()
            .map(|pt| {
                let lf = MultilinearExtension::new(pt.clone());
                lf.evaluate(config.embedding(), &ark_evals)
            })
            .collect();

        let prove_lf: Vec<Box<dyn LinearForm<Field64_3>>> = points_ext3
            .into_iter()
            .map(|pt| Box::new(MultilinearExtension::new(pt)) as Box<dyn LinearForm<Field64_3>>)
            .collect();

        let _final_claim = config.prove(
            &mut prover_state,
            vec![Cow::Borrowed(ark_evals.as_slice())],
            vec![Cow::Owned(witness)],
            prove_lf,
            Cow::Owned(per_point_evals.clone()),
        );

        let proof = prover_state.proof();

        let eval_proof = WhirEvalProof {
            narg_string: proof.narg_string,
            hints: proof.hints,
            #[cfg(debug_assertions)]
            pattern: proof.pattern,
        };

        (root, eval_proof, per_point_evals)
    }

    /// Verify a single-vector auxiliary WHIR proof at multiple evaluation points.
    ///
    /// SECURITY: Session name must match the one used during proving.
    pub fn verify_aux(
        &self,
        num_vars: usize,
        proof: &WhirEvalProof,
        eval_values: &[Field64_3],
        eval_points: &[&[GoldilocksField]],
        session_name: &str,
    ) -> Result<(), String> {
        assert_eq!(
            eval_values.len(),
            eval_points.len(),
            "eval_values length must match eval_points length"
        );

        let size = 1 << num_vars;
        let config = WhirConfig::<Basefield<Field64_3>>::new(size, &self.params);
        let ds = DomainSeparator::protocol(&config)
            .session(&session_name.to_string())
            .instance(&Empty);

        let proof_data = WhirProofData {
            narg_string: proof.narg_string.clone(),
            hints: proof.hints.clone(),
            #[cfg(debug_assertions)]
            pattern: proof.pattern.clone(),
        };

        let mut verifier_state = VerifierState::new_std(&ds, &proof_data);

        let commitment = config
            .receive_commitment(&mut verifier_state)
            .map_err(|e| format!("WHIR aux commitment verification failed: {:?}", e))?;

        let final_claim = config
            .verify(&mut verifier_state, &[&commitment], eval_values)
            .map_err(|e| format!("WHIR aux verification failed: {:?}", e))?;

        let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> = eval_points
            .iter()
            .map(|pt| {
                let ext3: Vec<Field64_3> = pt
                    .iter()
                    .map(|f| Field64_3::from(f.to_canonical_u64()))
                    .collect();
                Box::new(MultilinearExtension::new(ext3)) as Box<dyn LinearForm<Field64_3>>
            })
            .collect();

        final_claim
            .verify(
                verify_lf
                    .iter()
                    .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
            )
            .map_err(|e| format!("WHIR aux evaluation verification failed: {:?}", e))?;

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Legacy single-vector API (kept for backward compatibility)
    // ═══════════════════════════════════════════════════════════════════════

    /// Generate a WHIR proof with evaluation binding at a specific point.
    ///
    /// SECURITY: The evaluation value is computed internally using WHIR's
    /// `mixed_multilinear_extend` to ensure consistency with how WHIR verifies.
    /// If `eval_point` is None, uses a canonical evaluation point.
    /// Returns (commitment, proof, whir_eval_value) where whir_eval_value is the
    /// evaluation computed via WHIR's mixed_multilinear_extend (needed for verify).
    pub fn prove_at_point(
        &self,
        poly: &DenseMultilinearExtension<GoldilocksField>,
        eval_point: Option<&[GoldilocksField]>,
        _eval_value: Option<GoldilocksField>,
    ) -> (WhirCommitment, WhirEvalProof, Field64_3) {
        self.prove_at_point_with_session(poly, eval_point, WHIR_SESSION_NAME)
    }

    /// Generate a WHIR proof with a custom session name for domain separation.
    ///
    /// SECURITY: Different sub-protocols (preprocessed vs witness) MUST use
    /// different session names to prevent cross-protocol proof swapping.
    pub fn prove_at_point_with_session(
        &self,
        poly: &DenseMultilinearExtension<GoldilocksField>,
        eval_point: Option<&[GoldilocksField]>,
        session_name: &str,
    ) -> (WhirCommitment, WhirEvalProof, Field64_3) {
        let num_vars = poly.num_vars;
        let size = 1 << num_vars;
        let ark_evals = plonky2_vec_to_ark(&poly.evaluations);

        let config = WhirConfig::<Basefield<Field64_3>>::new(size, &self.params);
        let ds = DomainSeparator::protocol(&config)
            .session(&session_name.to_string())
            .instance(&Empty);

        let mut prover_state = ProverState::new_std(&ds);
        let witness = config.commit(&mut prover_state, &[&ark_evals]);

        // Build evaluation point — always compute value via WHIR's own evaluate()
        // to ensure consistency with verifier-side computation.
        let point_ext3: Vec<Field64_3> = if let Some(pt) = eval_point {
            pt.iter()
                .map(|f| Field64_3::from(f.to_canonical_u64()))
                .collect()
        } else {
            (0..num_vars)
                .map(|i| Field64_3::from((i + 1) as u64))
                .collect()
        };
        let lf = MultilinearExtension::new(point_ext3.clone());
        let eval_ext3 = lf.evaluate(config.embedding(), &ark_evals);

        let prove_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
            vec![Box::new(MultilinearExtension::new(point_ext3))];

        let _final_claim = config.prove(
            &mut prover_state,
            vec![Cow::Borrowed(ark_evals.as_slice())],
            vec![Cow::Owned(witness)],
            prove_lf,
            Cow::Owned(vec![eval_ext3]),
        );

        let proof = prover_state.proof();

        (
            WhirCommitment {
                proof_bytes: proof.narg_string.clone(),
            },
            WhirEvalProof {
                narg_string: proof.narg_string,
                hints: proof.hints,
                #[cfg(debug_assertions)]
                pattern: proof.pattern,
            },
            eval_ext3,
        )
    }

    /// Generate a WHIR proof with canonical evaluation point (legacy API).
    pub fn prove(
        &self,
        poly: &DenseMultilinearExtension<GoldilocksField>,
    ) -> (WhirCommitment, WhirEvalProof) {
        let (c, p, _) = self.prove_at_point(poly, None, None);
        (c, p)
    }

    /// Verify a WHIR proof with evaluation binding.
    ///
    /// If `eval_point` is provided, verifies that the committed polynomial
    /// evaluates correctly at that point (via WHIR's FinalClaim + linear form).
    /// `eval_value` is the expected evaluation (used as the claimed sum).
    /// If None, verifies only the commitment.
    pub fn verify(
        &self,
        num_vars: usize,
        proof: &WhirEvalProof,
        eval_point: Option<&[GoldilocksField]>,
        eval_value_ext3: Option<Field64_3>,
    ) -> Result<(), String> {
        self.verify_with_session(
            num_vars,
            proof,
            eval_point,
            eval_value_ext3,
            WHIR_SESSION_NAME,
        )
    }

    /// Verify a WHIR proof with a custom session name.
    ///
    /// SECURITY: The session name must match the one used during proving.
    /// Different sub-protocols use different session names to prevent
    /// cross-protocol proof confusion.
    pub fn verify_with_session(
        &self,
        num_vars: usize,
        proof: &WhirEvalProof,
        eval_point: Option<&[GoldilocksField]>,
        eval_value_ext3: Option<Field64_3>,
        session_name: &str,
    ) -> Result<(), String> {
        let size = 1 << num_vars;

        let config = WhirConfig::<Basefield<Field64_3>>::new(size, &self.params);
        let ds = DomainSeparator::protocol(&config)
            .session(&session_name.to_string())
            .instance(&Empty);

        let proof_data = WhirProofData {
            narg_string: proof.narg_string.clone(),
            hints: proof.hints.clone(),
            #[cfg(debug_assertions)]
            pattern: proof.pattern.clone(),
        };

        let mut verifier_state = VerifierState::new_std(&ds, &proof_data);

        let commitment = config
            .receive_commitment(&mut verifier_state)
            .map_err(|e| format!("WHIR commitment verification failed: {:?}", e))?;

        // Build evaluation point — must match prover's prove_at_point_with_session.
        // The prover always includes an evaluation at some point (canonical if None).
        // The verifier must match this exactly for transcript consistency.
        let point_ext3: Vec<Field64_3> = if let Some(pt) = eval_point {
            pt.iter()
                .map(|f| Field64_3::from(f.to_canonical_u64()))
                .collect()
        } else {
            // Canonical evaluation point (1, 2, 3, ..., n) — must match prover
            (0..num_vars)
                .map(|i| Field64_3::from((i + 1) as u64))
                .collect()
        };

        let has_eval_binding = eval_value_ext3.is_some();
        let evaluations: Vec<Field64_3> = if let Some(val) = eval_value_ext3 {
            vec![val]
        } else {
            // No expected value provided. We still must pass the evaluation
            // structure to match the prover's transcript (the prover always
            // includes an evaluation). We use a placeholder — the FinalClaim
            // linear form check will be skipped below.
            vec![Field64_3::from(0u64)]
        };

        let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
            vec![Box::new(MultilinearExtension::new(point_ext3)) as Box<dyn LinearForm<Field64_3>>];

        let final_claim = config
            .verify(&mut verifier_state, &[&commitment], &evaluations)
            .map_err(|e| format!("WHIR verification failed: {:?}", e))?;

        // Verify the linear form (evaluation at the claimed point).
        // Only check when the caller provided an expected eval value.
        // The proximity test (WHIR commitment binding) is always verified
        // by config.verify() above regardless.
        if has_eval_binding {
            final_claim
                .verify(
                    verify_lf
                        .iter()
                        .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
                )
                .map_err(|e| format!("WHIR evaluation verification failed: {:?}", e))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field as _;

    use super::*;

    #[test]
    fn test_field_conversion_roundtrip() {
        for i in 0..100u64 {
            let p2 = GoldilocksField::from_canonical_u64(i);
            let ark = plonky2_to_ark(p2);
            let back = ark_to_plonky2(ark);
            assert_eq!(p2, back, "Roundtrip failed for {i}");
        }

        let p = 0xFFFFFFFF00000001u64;
        for offset in [0u64, 1, 2, 100, 1000, 1 << 32, 1 << 53, p - 2, p - 1] {
            let val = offset.min(p - 1);
            let p2 = GoldilocksField::from_canonical_u64(val);
            let ark = plonky2_to_ark(p2);
            let back = ark_to_plonky2(ark);
            assert_eq!(p2, back, "Roundtrip failed for val={val}");
        }
    }

    #[test]
    fn test_field_arithmetic_consistency() {
        let a_p2 = GoldilocksField::from_canonical_u64(123456789);
        let b_p2 = GoldilocksField::from_canonical_u64(987654321);

        let a_ark = plonky2_to_ark(a_p2);
        let b_ark = plonky2_to_ark(b_p2);

        assert_eq!(a_p2 + b_p2, ark_to_plonky2(a_ark + b_ark));
        assert_eq!(a_p2 * b_p2, ark_to_plonky2(a_ark * b_ark));
        assert_eq!(a_p2.inverse(), ark_to_plonky2(a_ark.inverse().unwrap()));
    }

    #[test]
    fn test_whir_prove_verify_small() {
        let evals: Vec<GoldilocksField> = (0..16)
            .map(|i| GoldilocksField::from_canonical_u64(i + 1))
            .collect();
        let poly = DenseMultilinearExtension::new(evals);

        let pcs = WhirPCS::new(32, 0, 1, 2);
        let (_commitment, proof) = pcs.prove(&poly);

        let result = pcs.verify(poly.num_vars, &proof, None, None);
        assert!(result.is_ok(), "WHIR verify failed: {:?}", result.err());
    }

    #[test]
    fn test_whir_prove_verify_medium() {
        let evals: Vec<GoldilocksField> = (0..256)
            .map(|i| GoldilocksField::from_canonical_u64(i * 7 + 3))
            .collect();
        let poly = DenseMultilinearExtension::new(evals);

        let pcs = WhirPCS::new(32, 0, 1, 2);
        let (_commitment, proof) = pcs.prove(&poly);

        let result = pcs.verify(poly.num_vars, &proof, None, None);
        assert!(result.is_ok(), "WHIR verify failed: {:?}", result.err());
    }

    #[test]
    fn test_whir_prove_at_point_verify() {
        let evals: Vec<GoldilocksField> = (0..16)
            .map(|i| GoldilocksField::from_canonical_u64(i + 1))
            .collect();
        let poly = DenseMultilinearExtension::new(evals);
        let num_vars = poly.num_vars;

        let pcs = WhirPCS::new(32, 0, 1, 2);

        // Simulate a sumcheck-derived evaluation point
        let eval_point: Vec<GoldilocksField> = (0..num_vars)
            .map(|i| GoldilocksField::from_canonical_u64((i as u64) * 3 + 7))
            .collect();

        // Prove with eval binding — eval_ext3 is computed internally by prove_at_point
        let (_commitment, proof, eval_ext3) = pcs.prove_at_point(&poly, Some(&eval_point), None);

        // Verify with evaluation binding — pass the same Ext3 value
        let result = pcs.verify(num_vars, &proof, Some(&eval_point), Some(eval_ext3));
        assert!(
            result.is_ok(),
            "prove_at_point verify failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_whir_split_commit_prove_verify_single_point() {
        // Two vectors of size 16 (4 variables), single evaluation point
        let evals_a: Vec<ArkGoldilocks> = (0..16)
            .map(|i| ArkGoldilocks::from((i + 1) as u64))
            .collect();
        let evals_b: Vec<ArkGoldilocks> = (0..16)
            .map(|i| ArkGoldilocks::from((i * 3 + 7) as u64))
            .collect();

        let pcs = WhirPCS::new(32, 0, 1, 2);

        // Split commit
        let commit_data = pcs.commit_split(&[&evals_a, &evals_b], WHIR_SESSION_SPLIT);

        // Verify we got per-vector roots
        assert_eq!(commit_data.roots.len(), 2);
        assert_eq!(commit_data.roots[0].len(), 32);
        assert_eq!(commit_data.roots[1].len(), 32);
        assert_ne!(commit_data.roots[0], commit_data.roots[1]);

        let num_vars = commit_data.num_vars;

        // Simulate sumcheck output point (non-canonical)
        let eval_point: Vec<GoldilocksField> = (0..num_vars)
            .map(|i| GoldilocksField::from_canonical_u64((i as u64) * 3 + 7))
            .collect();

        // Prove at sumcheck output point
        let (eval_proof, per_point_evals) = pcs.prove_split_with_eval(commit_data, &[&eval_point]);
        assert_eq!(per_point_evals.len(), 1); // 1 point
        assert_eq!(per_point_evals[0].len(), 2); // 2 vectors

        // Flatten evaluations for verify
        let flat_evals: Vec<Field64_3> = per_point_evals.into_iter().flatten().collect();

        // Verify
        let result = pcs.verify_split(
            num_vars,
            &eval_proof,
            &flat_evals,
            WHIR_SESSION_SPLIT,
            &[&eval_point],
            2, // num_vectors
        );
        assert!(result.is_ok(), "Split verify failed: {:?}", result.err());
    }

    #[test]
    fn test_whir_split_commit_prove_verify_two_points() {
        // Two vectors, TWO evaluation points (simulating r and r_perm)
        let evals_a: Vec<ArkGoldilocks> = (0..16)
            .map(|i| ArkGoldilocks::from((i + 1) as u64))
            .collect();
        let evals_b: Vec<ArkGoldilocks> = (0..16)
            .map(|i| ArkGoldilocks::from((i * 3 + 7) as u64))
            .collect();

        let pcs = WhirPCS::new(32, 0, 1, 2);
        let commit_data = pcs.commit_split(&[&evals_a, &evals_b], WHIR_SESSION_SPLIT);
        let num_vars = commit_data.num_vars;

        // Two distinct evaluation points (constraint r and permutation r_perm)
        let r: Vec<GoldilocksField> = (0..num_vars)
            .map(|i| GoldilocksField::from_canonical_u64((i as u64) * 3 + 7))
            .collect();
        let r_perm: Vec<GoldilocksField> = (0..num_vars)
            .map(|i| GoldilocksField::from_canonical_u64((i as u64) * 11 + 2))
            .collect();

        // Prove at both points
        let (eval_proof, per_point_evals) = pcs.prove_split_with_eval(commit_data, &[&r, &r_perm]);
        assert_eq!(per_point_evals.len(), 2); // 2 points
        assert_eq!(per_point_evals[0].len(), 2); // 2 vectors each

        // Evaluations at different points should differ
        assert_ne!(per_point_evals[0], per_point_evals[1]);

        // Flatten: [P_a(r), P_b(r), P_a(r_perm), P_b(r_perm)]
        let flat_evals: Vec<Field64_3> = per_point_evals.into_iter().flatten().collect();
        assert_eq!(flat_evals.len(), 4);

        // Verify
        let result = pcs.verify_split(
            num_vars,
            &eval_proof,
            &flat_evals,
            WHIR_SESSION_SPLIT,
            &[&r, &r_perm],
            2, // num_vectors
        );
        assert!(
            result.is_ok(),
            "Two-point split verify failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_split_commit_root_matches_standalone() {
        // The root from commit_root() must match the root from commit_split()
        // for the same polynomial (both use WHIR_SESSION_SPLIT).
        let gl_evals: Vec<GoldilocksField> = (0..16)
            .map(|i| GoldilocksField::from_canonical_u64(i + 1))
            .collect();
        let poly = DenseMultilinearExtension::new(gl_evals.clone());

        let pcs = WhirPCS::new(32, 0, 1, 2);

        // Standalone root
        let standalone_root = pcs.commit_root(&poly);

        // Split commit root (first vector)
        let ark_evals = plonky2_vec_to_ark(&poly.evaluations);
        let dummy_evals: Vec<ArkGoldilocks> = (0..16)
            .map(|i| ArkGoldilocks::from((i * 5 + 3) as u64))
            .collect();
        let commit_data = pcs.commit_split(&[&ark_evals, &dummy_evals], WHIR_SESSION_SPLIT);

        assert_eq!(
            standalone_root, commit_data.roots[0],
            "commit_root() must produce the same root as commit_split()[0]"
        );
    }
}
