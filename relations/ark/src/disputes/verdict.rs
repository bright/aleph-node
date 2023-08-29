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
        crate::environment::FpVar,
        ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::FieldVar},
        ark_relations::{ns, r1cs::SynthesisError::UnconstrainedVariable},
        ark_std::Zero,
        core::cmp::Ordering,
        liminal_ark_poseidon::circuit::two_to_one_hash,
    };

    use crate::disputes::{
        hash_to_field,
        types::{
            BackendHash, BackendHashes, BackendVotes, BackendVotesSum, FrontendHash,
            FrontendHashes, FrontendVotes, FrontendVotesSum,
        },
        vec_of_hashes_to_fields, vec_of_votes_to_fields,
    };

    use crate::environment::CircuitField;

    #[relation_object_definition]
    #[derive(Clone, Debug)]
    struct VerdictRelation {
        #[constant]
        pub max_votes_len: u8,

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
        pub votes_sum: BackendVotesSum,
        #[public_input(frontend_type = "FrontendHash", parse_with = "hash_to_field")]
        pub hashed_votes: BackendHash,
    }

    #[cfg(feature = "circuit")]
    #[circuit_definition]
    fn generate_constraints() {
        let max_votes_len = self.max_votes_len().clone();
        let votes = &self.decoded_votes().cloned().unwrap_or_default();
        let hashed_shared_keys = &self.hashed_shared_keys().cloned().unwrap_or_default();
        if votes.len() > max_votes_len as usize {
            return Err(UnconstrainedVariable);
        }
        if hashed_shared_keys.len() != votes.len() {
            return Err(UnconstrainedVariable);
        }

        let votes_sum = FpVar::new_input(ns!(cs.clone(), "votes_sum"), || self.votes_sum())?;
        let hashed_verdict =
            FpVar::new_input(ns!(cs.clone(), "hashed_votes"), || self.hashed_votes())?;

        let one = FpVar::new_constant(ns!(cs, "positive"), CircuitField::from(1u64))?;
        let zero = FpVar::new_constant(ns!(cs, "negative"), CircuitField::from(0u64))?;

        let zero_vote = CircuitField::zero();
        let mut computed_hash = FpVar::one();
        let mut computed_votes = FpVar::zero();
        for i in 0..max_votes_len as usize {
            let vote = FpVar::new_witness(ns!(cs.clone(), "vote"), || {
                Ok(votes.get(i).unwrap_or(&zero_vote))
            })?;
            let shared_key = FpVar::new_witness(ns!(cs, "key"), || {
                Ok(hashed_shared_keys.get(i).unwrap_or(&zero_vote))
            })?;

            //---------------------------------------
            // Check if vote is valid, can be: [0,1]
            //---------------------------------------
            vote.enforce_cmp(&one, Ordering::Less, true)?;
            vote.enforce_cmp(&zero, Ordering::Greater, true)?;

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

        //-------------------------------------------
        // Check if computed sum of votes is correct
        //-------------------------------------------
        votes_sum.enforce_equal(&computed_votes)?;

        Ok(())
    }
}

#[cfg(all(test, feature = "circuit"))]
mod tests {
    use super::{
        VerdictRelationWithFullInput, VerdictRelationWithPublicInput, VerdictRelationWithoutInput,
    };
    use crate::disputes::ecdh::{Ecdh, EcdhScheme};
    use crate::disputes::types::{FrontendHashes, FrontendVotes};
    use crate::disputes::vote_to_filed;
    use crate::environment::CircuitField;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::SNARK;
    use ark_ed_on_bls12_381::{
        EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub, Fr as JubJubFr,
    };
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::{One, Zero};
    use liminal_ark_poseidon::hash::two_to_one_hash;

    const MAX_VOTES_LEN: u8 = 4;

    fn get_circuit_with_full_input() -> VerdictRelationWithFullInput {
        let rng = &mut ark_std::test_rng();

        let votes = vec![1u8, 1u8, 0u8];

        // Generate Judge and Jurors pub/priv keys
        let (pub_judge, priv_judge) = Ecdh::<JubJub>::generate_keys(rng);
        let jurors_keys = (0..votes.len())
            .map(|_| Ecdh::<JubJub>::generate_keys(rng))
            .collect::<Vec<(_, _)>>();

        let key_zero = (JubJubAffine::zero(), JubJubFr::zero());
        let mut hashed_shared_keys = FrontendHashes::new();
        let mut hashed_votes = CircuitField::one();
        let mut front_votes = FrontendVotes::new();
        for i in 0..MAX_VOTES_LEN as usize {
            // Prepare input votes
            let v = votes.get(i).unwrap_or(&0u8);
            front_votes.push(*v);

            // Prepare hash of votes and shared key
            let k = jurors_keys.get(i).unwrap_or(&key_zero);
            let shared_jure_key = Ecdh::<JubJub>::make_shared_key(pub_judge, k.1);
            let shared_jure_key = two_to_one_hash([shared_jure_key.x, shared_jure_key.y]);
            hashed_votes =
                two_to_one_hash([vote_to_filed(*v) + shared_jure_key.clone(), hashed_votes]);

            // Prepare inputs votes
            let shared_judge_key = Ecdh::<JubJub>::make_shared_key(k.0, priv_judge);
            let shared_judge_key = two_to_one_hash([shared_judge_key.x, shared_judge_key.y]);
            hashed_shared_keys.push(shared_judge_key.0 .0);
        }

        let sum: u8 = votes.iter().map(|v| *v as u8).sum();
        VerdictRelationWithFullInput::new(
            MAX_VOTES_LEN,
            sum,
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
        let circuit_without_input = VerdictRelationWithoutInput::new(MAX_VOTES_LEN);

        let mut rng = ark_std::test_rng();
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap();

        let circuit_with_full_input = get_circuit_with_full_input();
        let proof = Groth16::prove(&pk, circuit_with_full_input, &mut rng).unwrap();

        let circuit_with_public_input: VerdictRelationWithPublicInput =
            get_circuit_with_full_input().into();
        let input = circuit_with_public_input.serialize_public_input();

        let valid_proof = Groth16::verify(&vk, &input, &proof).unwrap();
        assert!(valid_proof);
    }
}
