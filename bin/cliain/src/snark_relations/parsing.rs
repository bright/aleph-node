use std::str::FromStr;

use anyhow::{anyhow, Error, Result};
use clap::ValueEnum;
use liminal_ark_relations::disputes::{FrontendHash, FrontendHashes, FrontendVotes};
use liminal_ark_relations::shielder::types::{FrontendAccount, FrontendMerklePath, FrontendNote};

use crate::snark_relations::{
    systems::SomeProvingSystem, NonUniversalProvingSystem, UniversalProvingSystem,
};

pub fn parse_frontend_hash(frontend_hash: &str) -> Result<FrontendHash> {
    frontend_hash
        .split(',')
        .map(|l| u64::from_str(l).expect("Each element should be a valid `u64`"))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|e| anyhow!("Hash consists of 4 `u64` elements: {e:?}"))
}

pub fn parse_frontend_hashes(frontend_hashes: &str) -> Result<FrontendHashes> {
    Ok(frontend_hashes
        .split(':')
        .map(|n| parse_frontend_hash(n).expect("Each element should be valid hash"))
        .collect::<Vec<_>>())
}

pub fn parse_frontend_votes(frontend_votes: &str) -> Result<FrontendVotes> {
    Ok(frontend_votes
        .split(',')
        .map(|l| u8::from_str(l).expect("Each element should be a valid `u8`"))
        .collect::<Vec<_>>())
}

pub fn parse_frontend_note(frontend_note: &str) -> Result<FrontendNote> {
    frontend_note
        .split(',')
        .map(|l| u64::from_str(l).expect("Each element should be a valid `u64`"))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|e| anyhow!("Note consists of 4 `u64` elements: {e:?}"))
}

pub fn parse_frontend_merkle_path(frontend_merkle_path: &str) -> Result<FrontendMerklePath> {
    Ok(frontend_merkle_path
        .split(':')
        .map(|n| parse_frontend_note(n).expect("Each node should be valid note"))
        .collect::<Vec<_>>())
}

pub fn parse_frontend_account(frontend_account: &str) -> Result<FrontendAccount> {
    Ok(frontend_account
        .split(',')
        .map(|x| u8::from_str(x).expect("Each element should be a valid `u8`"))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap())
}

pub fn parse_some_system(system: &str) -> Result<SomeProvingSystem> {
    let maybe_universal =
        UniversalProvingSystem::from_str(system, true).map(SomeProvingSystem::Universal);
    let maybe_non_universal =
        NonUniversalProvingSystem::from_str(system, true).map(SomeProvingSystem::NonUniversal);
    maybe_universal.or(maybe_non_universal).map_err(Error::msg)
}
