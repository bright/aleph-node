use liminal_ark_relation_macro::snark_relation;

/// `Vote` relation for the BrightDisputes application.
///
/// It express the facts that:
///  - `vote` can be value of `0` or `1` (private input)
///  - `hashed_shared_key` is a hash of the shared key (private input)
///  - `encrypted_vote` is a result of the encryption `vote` with the `hashed_shared_key` (public input)
#[snark_relation]
mod relation {
    #[cfg(feature = "circuit")]
    use {
        crate::environment::FpVar,
        ark_r1cs_std::{alloc::AllocVar, eq::EqGadget},
        ark_relations::ns,
        core::cmp::Ordering,
    };

    use crate::environment::CircuitField;

    use crate::disputes::{
        hash_to_field,
        types::{BackendHash, BackendVote, FrontendHash, FrontendVote},
    };

    #[relation_object_definition]
    #[derive(Clone, Debug)]
    struct VoteRelation {
        // Private inputs
        #[private_input(frontend_type = "FrontendVote")]
        pub vote: BackendVote,
        #[private_input(frontend_type = "FrontendHash", parse_with = "hash_to_field")]
        pub hashed_shared_key: BackendHash,

        // Public inputs
        #[public_input(frontend_type = "FrontendHash", parse_with = "hash_to_field")]
        pub encrypted_vote: BackendHash,
    }

    #[cfg(feature = "circuit")]
    #[circuit_definition]
    fn generate_constraints() {
        let vote = FpVar::new_witness(ns!(cs, "vote"), || self.vote())?;
        let hashed_shared_key =
            FpVar::new_witness(ns!(cs, "hashed_shared_key"), || self.hashed_shared_key())?;
        let encrypted_vote = FpVar::new_input(ns!(cs, "encrypted_vote"), || self.encrypted_vote())?;

        //---------------------------------------
        // Check if vote has valid values: [0,1]
        //---------------------------------------
        let one = FpVar::new_constant(ns!(cs, "positive"), CircuitField::from(1u64))?;
        let zero = FpVar::new_constant(ns!(cs, "negative"), CircuitField::from(0u64))?;
        vote.enforce_cmp(&one, Ordering::Less, true)?;
        vote.enforce_cmp(&zero, Ordering::Greater, true)?;

        //---------------------------------------
        // Check if vote was created from the 
        // hash of the shared key.
        //---------------------------------------
        let hash_result = vote + hashed_shared_key;
        encrypted_vote.enforce_equal(&hash_result)?;

        Ok(())
    }
}

#[cfg(all(test, feature = "circuit"))]
mod tests {
    use super::{VoteRelationWithFullInput, VoteRelationWithPublicInput, VoteRelationWithoutInput};
    use crate::disputes::ecdh::{Ecdh, EcdhScheme};
    use crate::disputes::vote_to_filed;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::SNARK;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use liminal_ark_poseidon::hash::two_to_one_hash;

    fn get_circuit_with_full_input() -> VoteRelationWithFullInput {
        let rng = &mut ark_std::test_rng();
        let (pub_judge, _) = Ecdh::<JubJub>::generate_keys(rng);
        let (_, priv_juror) = Ecdh::<JubJub>::generate_keys(rng);
        let hashed_shared_key = Ecdh::<JubJub>::make_shared_key(pub_judge, priv_juror);
        let hashed_shared_key = two_to_one_hash([hashed_shared_key.x, hashed_shared_key.y]);
        let vote: u8 = 1;
        let encrypted_vote = vote_to_filed(vote) + hashed_shared_key;

        VoteRelationWithFullInput::new(encrypted_vote.0 .0, vote, hashed_shared_key.0 .0)
    }

    #[test]
    fn vote_constraints_correctness() {
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
    fn vote_proving_procedure() {
        let circuit_without_input = VoteRelationWithoutInput::new();

        let mut rng = ark_std::test_rng();
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap();

        let circuit_with_full_input = get_circuit_with_full_input();
        let proof = Groth16::prove(&pk, circuit_with_full_input, &mut rng).unwrap();

        let circuit_with_public_input: VoteRelationWithPublicInput =
            get_circuit_with_full_input().into();
        let input = circuit_with_public_input.serialize_public_input();

        let valid_proof = Groth16::verify(&vk, &input, &proof).unwrap();
        assert!(valid_proof);
    }
}
