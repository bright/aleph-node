use ark_std::vec::Vec;

use crate::environment::CircuitField;

// Types accepted by the relation constructors.
pub type FrontendVote = u8;
pub type FrontendVerdict = u8;
pub type FrontendHash = [u64; 4];
pub type FrontendHashes = Vec<FrontendHash>;
pub type FrontendVotes = Vec<FrontendVote>;
pub type FrontendVotesSum = u8;

// Types used internally by the relations (but still outside circuit environment).
pub type BackendVote = CircuitField;
pub type BackendVerdict = CircuitField;
pub type BackendVotes = Vec<BackendVote>;
pub type BackendHash = CircuitField;
pub type BackendHashes = Vec<CircuitField>;
pub type BackendVotesSum = CircuitField;
