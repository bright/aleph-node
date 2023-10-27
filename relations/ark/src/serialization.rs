use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec, vec::Vec};

pub fn serialize<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = vec![0; t.serialized_size()];
    t.serialize(&mut bytes[..]).expect("Failed to serialize");
    bytes.to_vec()
}

pub fn deserialize<T: CanonicalDeserialize>(bytes: &Vec<u8>) -> T {
    T::deserialize(&bytes[..]).expect("Failed to deserialize")
}
