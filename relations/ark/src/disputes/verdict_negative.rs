use liminal_ark_relation_macro::snark_relation;

/// `Verdict` relation for the BrightDisputes application.
///
/// It express the facts that:
///  - `decoded_votes` is a vector of decoded votes, which can be 0 or 1 (private input).
///  - `hashed_shared_keys` is a vector of hashed shared keys. The order of the keys should
///     correspond to the order of the decoded votes (private input).
///  - `votes_sum` is a sum of all decoded votes (public input).
///  - `hashed_votes` is a single hash of all encoded votes. Each vote is encoded with
///     the corresponding hash of the shared key (public input).
/// The relation has one constant input `max_votes_len` which specify the maximum number of votes
#[snark_relation]
mod relation {
    #[cfg(feature = "circuit")]
    use {
        crate::disputes::{VerdictRelation, MAX_VOTES_LEN},
        crate::environment::{CircuitField, FpVar},
        ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::FieldVar},
        ark_relations::{ns, r1cs::SynthesisError::UnconstrainedVariable},
        ark_std::Zero,
        core::cmp::Ordering,
        liminal_ark_poseidon::circuit::two_to_one_hash,
    };

    use crate::disputes::{
        hash_to_field,
        types::{
            BackendHash, BackendHashes, BackendVerdict, BackendVotes, BackendVotesSum,
            FrontendHash, FrontendHashes, FrontendVerdict, FrontendVotes, FrontendVotesSum,
        },
        vec_of_hashes_to_fields, vec_of_votes_to_fields,
    };

    #[relation_object_definition]
    #[derive(Clone, Debug)]
    struct VerdictNegativeRelation {
        // Private inputs
        #[private_input(frontend_type = "FrontendVotes", parse_with = "vec_of_votes_to_fields")]
        pub decoded_votes: BackendVotes,
        #[private_input(
            frontend_type = "FrontendHashes",
            parse_with = "vec_of_hashes_to_fields"
        )]
        pub hashed_shared_keys: BackendHashes,

        // Public inputs
        #[public_input(frontend_type = "FrontendVotesSum")]
        pub max_votes: BackendVotesSum,
        #[public_input(frontend_type = "FrontendVerdict")]
        pub verdict: BackendVerdict,
        #[public_input(frontend_type = "FrontendHash", parse_with = "hash_to_field")]
        pub hashed_votes: BackendHash,
    }

    #[cfg(feature = "circuit")]
    #[circuit_definition]
    fn generate_constraints() {
        let votes = &self.decoded_votes().cloned().unwrap_or_default();
        let hashed_shared_keys = &self.hashed_shared_keys().cloned().unwrap_or_default();
        if votes.len() > MAX_VOTES_LEN as usize {
            return Err(UnconstrainedVariable);
        }
        if hashed_shared_keys.len() != votes.len() {
            return Err(UnconstrainedVariable);
        }

        let max_votes = FpVar::new_input(ns!(cs.clone(), "max_votes"), || self.max_votes())?;
        let verdict = FpVar::new_input(ns!(cs.clone(), "verdict"), || self.verdict())?;
        let hashed_verdict =
            FpVar::new_input(ns!(cs.clone(), "hashed_votes"), || self.hashed_votes())?;

        let zero_vote = CircuitField::zero();
        let mut computed_hash = FpVar::one();
        let mut computed_votes = FpVar::zero();
        for i in 0..MAX_VOTES_LEN as usize {
            let vote = FpVar::new_witness(ns!(cs.clone(), "vote"), || {
                Ok(votes.get(i).unwrap_or(&zero_vote))
            })?;
            let shared_key = FpVar::new_witness(ns!(cs, "key"), || {
                Ok(hashed_shared_keys.get(i).unwrap_or(&zero_vote))
            })?;

            //--------------------
            // Counting the votes
            //--------------------
            computed_votes += vote.clone();

            //----------------------------------------
            // Computing the hash of all hashed votes
            //----------------------------------------
            computed_hash = two_to_one_hash(cs.clone(), [vote + shared_key, computed_hash])?;
        }

        //-----------------------------------
        // Check if computed hash is correct
        //-----------------------------------
        hashed_verdict.enforce_equal(&computed_hash)?;

        //-------------------------------------------------
        // Check if computed votes meet verdict conditions
        //-------------------------------------------------
        computed_votes.enforce_cmp(&max_votes, Ordering::Less, true)?;

        //-------------------------------------------
        // Check if verdict correspond to right case
        //-------------------------------------------
        let limit = FpVar::new_constant(
            ns!(cs, "verdict_value"),
            CircuitField::from(VerdictRelation::Negative as u64),
        )?;
        verdict.enforce_equal(&limit)?;

        Ok(())
    }
}

#[cfg(all(test, feature = "circuit"))]
mod tests {
    use super::{
        VerdictNegativeRelationWithFullInput, VerdictNegativeRelationWithPublicInput,
        VerdictNegativeRelationWithoutInput,
    };
    use crate::disputes::ecdh::{Ecdh, EcdhScheme};
    use crate::disputes::types::{FrontendHashes, FrontendVotes};
    use crate::disputes::{vote_to_filed, VerdictRelation, MAX_VOTES_LEN};
    use crate::environment::CircuitField;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::SNARK;
    use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::{One, Zero};
    use liminal_ark_poseidon::hash::two_to_one_hash;

    fn get_circuit_with_full_input() -> VerdictNegativeRelationWithFullInput {
        let votes = vec![1u8, 0u8, 0u8];

        let judge_priv_key = Ecdh::<JubJub>::deserialize_private_key(vec![
            179, 27, 40, 132, 173, 160, 20, 202, 37, 182, 11, 160, 160, 193, 117, 27, 17, 178, 148,
            170, 121, 97, 7, 150, 28, 76, 125, 99, 218, 205, 155, 2,
        ]);

        let juror4_pub = Ecdh::<JubJub>::deserialize_public_key(vec![
            174, 61, 91, 130, 0, 47, 103, 34, 226, 225, 196, 241, 107, 143, 140, 77, 138, 88, 192,
            255, 93, 86, 69, 59, 169, 166, 118, 78, 127, 242, 91, 215,
        ]);
        let juror5_pub = Ecdh::<JubJub>::deserialize_public_key(vec![
            143, 109, 129, 121, 68, 184, 58, 48, 140, 51, 133, 12, 113, 247, 135, 121, 221, 88,
            110, 197, 186, 199, 169, 56, 133, 7, 65, 135, 188, 239, 9, 227,
        ]);
        let juror6_pub = Ecdh::<JubJub>::deserialize_public_key(vec![
            41, 242, 196, 80, 238, 65, 144, 105, 235, 230, 62, 236, 224, 8, 170, 129, 164, 1, 112,
            7, 126, 227, 179, 230, 62, 154, 68, 169, 152, 186, 138, 64,
        ]);

        let jurors_keys = vec![juror4_pub, juror5_pub, juror6_pub];
        let key_zero = JubJubAffine::zero();
        let max_sum: u8 = 1;
        let mut hashed_shared_keys = FrontendHashes::new();
        let mut hashed_votes = CircuitField::one();
        let mut front_votes = FrontendVotes::new();
        for i in 0..MAX_VOTES_LEN as usize {
            // Prepare input votes
            let v = votes.get(i).unwrap_or(&0u8);
            front_votes.push(*v);

            // Prepare hash of votes and shared key
            let juror_pub = jurors_keys.get(i).unwrap_or(&key_zero);
            let shared_key = Ecdh::<JubJub>::make_shared_key(*juror_pub, judge_priv_key);
            let shared_key = two_to_one_hash([shared_key.x, shared_key.y]);
            hashed_votes = two_to_one_hash([vote_to_filed(*v) + shared_key.clone(), hashed_votes]);

            // Prepare inputs votes
            hashed_shared_keys.push(shared_key.0 .0);
        }

        VerdictNegativeRelationWithFullInput::new(
            max_sum,
            VerdictRelation::Negative as u8,
            hashed_votes.0 .0,
            front_votes,
            hashed_shared_keys,
        )
    }

    #[test]
    fn verdict_constraints_correctness() {
        let circuit = get_circuit_with_full_input();

        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            println!("{:?}", cs.which_is_unsatisfied());
        }

        assert!(is_satisfied);
    }

    #[test]
    fn verdict_proving_procedure() {
        let circuit_without_input = VerdictNegativeRelationWithoutInput::new();

        let mut rng = ark_std::test_rng();
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap();

        let circuit_with_full_input = get_circuit_with_full_input();
        let proof = Groth16::prove(&pk, circuit_with_full_input, &mut rng).unwrap();

        let circuit_with_public_input: VerdictNegativeRelationWithPublicInput =
            get_circuit_with_full_input().into();
        let input = circuit_with_public_input.serialize_public_input();

        let valid_proof = Groth16::verify(&vk, &input, &proof).unwrap();
        assert!(valid_proof);
    }
}
