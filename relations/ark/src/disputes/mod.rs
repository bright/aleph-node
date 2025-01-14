pub mod ecdh;
mod types;
mod verdict_negative;
mod verdict_none;
mod verdict_positive;
mod vote;

pub use types::{
    BackendHash, BackendHashes, BackendVote, BackendVotes, FrontendHash, FrontendHashes,
    FrontendVerdict, FrontendVote, FrontendVotes, FrontendVotesSum,
};

use ark_ed_on_bls12_381::EdwardsAffine as JubJub;
use ark_ff::BigInteger256;
use liminal_ark_poseidon::hash::two_to_one_hash;

#[derive(Debug)]
pub enum Error {
    InvalidSize,
}

#[derive(Debug)]
pub enum VerdictRelation {
    None = 1,
    Negative = 2,
    Positive = 3,
}

pub use verdict_negative::{
    VerdictNegativeRelationWithFullInput, VerdictNegativeRelationWithPublicInput,
    VerdictNegativeRelationWithoutInput,
};
pub use verdict_none::{
    VerdictNoneRelationWithFullInput, VerdictNoneRelationWithPublicInput,
    VerdictNoneRelationWithoutInput,
};
pub use verdict_positive::{
    VerdictPositiveRelationWithFullInput, VerdictPositiveRelationWithPublicInput,
    VerdictPositiveRelationWithoutInput,
};
pub use vote::{VoteRelationWithFullInput, VoteRelationWithPublicInput, VoteRelationWithoutInput};

use crate::environment::CircuitField;

pub const MAX_VOTES_LEN: u8 = 9;

pub fn hash_to_field(hash: FrontendHash) -> BackendHash {
    BackendHash::new(BigInteger256::new(hash))
}

pub fn vec_of_hashes_to_fields(hashes: FrontendHashes) -> BackendHashes {
    hashes.into_iter().map(hash_to_field).collect()
}

pub fn vote_to_filed(vote: FrontendVote) -> BackendVote {
    BackendVote::from(vote as u64)
}

pub fn field_to_vote(field: BackendVote) -> FrontendVote {
    let big: BigInteger256 = field.into();
    big.0[0] as FrontendVote
}

pub fn vec_of_votes_to_fields(front: FrontendVotes) -> BackendVotes {
    front.into_iter().map(vote_to_filed).collect()
}

pub fn make_shared_key_hash(shared_key: JubJub) -> BackendHash {
    two_to_one_hash([shared_key.x, shared_key.y])
}

pub fn make_two_to_one_hash(val1: CircuitField, val2: CircuitField) -> CircuitField {
    two_to_one_hash([val1, val2])
}

pub fn hash_two_to_one(val1: FrontendHash, val2: FrontendHash) -> FrontendHash {
    let field = two_to_one_hash([hash_to_field(val1), hash_to_field(val2)]);
    field.0 .0
}

#[cfg(all(test))]
pub mod tests {
    use super::*;
    use crate::environment::CircuitField;

    #[test]
    fn test_hash_to_field() {
        let field = CircuitField::from(431u64);
        let hash: FrontendHash = field.0 .0;
        assert_eq!(field, hash_to_field(hash));
    }

    #[test]
    fn test_vec_of_hashes_to_fields() {
        let fields: BackendHashes = (0..10)
            .into_iter()
            .map(|v| CircuitField::from(v as u64))
            .collect();
        let hashes: FrontendHashes = fields.iter().map(|f| f.0 .0).collect();
        assert_eq!(fields, vec_of_hashes_to_fields(hashes));
    }

    #[test]
    fn test_message_to_field() {
        for i in 0..u8::MAX {
            let msg_field = vote_to_filed(i);
            let msg = field_to_vote(msg_field);
            assert_eq!(i, msg);
        }
    }

    #[test]
    fn test_vec_of_votes_to_fields() {
        let votes: FrontendVotes = (0..10).into_iter().map(|v| v % 2).collect();
        let fields: BackendHashes = votes
            .iter()
            .map(|v| CircuitField::from(*v as u64))
            .collect();
        assert_eq!(fields, vec_of_votes_to_fields(votes));
    }

    #[test]
    fn test_hash_two_to_one() {
        let votes: FrontendVotes = (0..10).into_iter().map(|v| v % 2).collect();
        let fields: BackendHashes = votes
            .iter()
            .map(|v| CircuitField::from(*v as u64))
            .collect();
        assert_eq!(fields, vec_of_votes_to_fields(votes));
    }
}
