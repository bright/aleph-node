use crate::{
    serialization::{deserialize, serialize},
    CanonicalSerialize,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{bytes::ToBytes, fields::PrimeField, UniformRand};
use ark_std::{hash::Hash, io::Cursor, marker::PhantomData, rand::Rng, vec, vec::Vec};

/// A simple trait for generating a pub/priv keys and creating an ECDH shred key.
pub trait EcdhScheme {
    type PrivateKey: ToBytes + Clone + Default;
    type PublicKey: ToBytes + Hash + Eq + Clone + Default + Send + Sync;
    type SharedKey: ToBytes + Hash + Eq + Clone + Default + Send + Sync;

    /// Generate a pair of public and private keys.
    fn generate_keys<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::PrivateKey);
    /// Create a shared key, based on public and private key.
    fn make_shared_key(
        public_key: Self::PublicKey,
        private_key: Self::PrivateKey,
    ) -> Self::SharedKey;

    /// Serialize public key
    fn serialize_public_key(public_key: Self::PublicKey) -> Vec<u8>;
    /// Deserialize public key
    fn deserialize_public_key(public_key: Vec<u8>) -> Self::PublicKey;

    /// Serialize private key
    fn serialize_private_key(private_key: Self::PrivateKey) -> Vec<u8>;
    /// Deserialize private key
    fn deserialize_private_key(private_key: Vec<u8>) -> Self::PrivateKey;
}

pub struct Ecdh<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;
pub type PrivateKey<C> = <C as ProjectiveCurve>::ScalarField;
pub type SharedKey<C> = <C as ProjectiveCurve>::Affine;

impl<C: ProjectiveCurve> EcdhScheme for Ecdh<C>
where
    C::ScalarField: PrimeField,
{
    type PublicKey = PublicKey<C>;
    type PrivateKey = PrivateKey<C>;
    type SharedKey = SharedKey<C>;

    fn generate_keys<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::PrivateKey) {
        let priv_key = C::ScalarField::rand(rng);
        let pub_key: Self::PublicKey = C::prime_subgroup_generator().into();
        (pub_key.mul(priv_key).into(), priv_key)
    }

    fn make_shared_key(
        public_key: Self::PublicKey,
        private_key: Self::PrivateKey,
    ) -> Self::SharedKey {
        public_key.mul(private_key).into()
    }

    fn serialize_public_key(public_key: Self::PublicKey) -> Vec<u8> {
        let buf_size = C::zero().serialized_size();
        let mut serialized = vec![0; buf_size];
        let mut cursor = Cursor::new(&mut serialized[..]);
        public_key.serialize(&mut cursor).unwrap();
        serialized
    }

    fn deserialize_public_key(public_key: Vec<u8>) -> Self::PublicKey {
        let mut cursor = Cursor::new(&public_key[..]);
        C::deserialize(&mut cursor).unwrap().into()
    }

    fn serialize_private_key(private_key: Self::PrivateKey) -> Vec<u8> {
        serialize(&private_key)
    }

    fn deserialize_private_key(bytes: Vec<u8>) -> Self::PrivateKey {
        deserialize(&bytes)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;

    #[test]
    fn test_ecdh() {
        let rng = &mut ark_std::test_rng();

        let (pub_alice, priv_alice) = Ecdh::<JubJub>::generate_keys(rng);
        let (pub_bob, priv_bob) = Ecdh::<JubJub>::generate_keys(rng);

        assert_ne!(priv_alice, priv_bob);
        assert_ne!(pub_alice, pub_bob);

        let shared_alice = Ecdh::<JubJub>::make_shared_key(pub_alice, priv_bob);
        let shared_bob = Ecdh::<JubJub>::make_shared_key(pub_bob, priv_alice);
        assert_eq!(shared_alice, shared_bob);

        let sh_key_alice =
            liminal_ark_poseidon::hash::two_to_one_hash([shared_alice.x, shared_alice.y]);
        let sh_key_bob = liminal_ark_poseidon::hash::two_to_one_hash([shared_bob.x, shared_bob.y]);

        assert_eq!(sh_key_alice, sh_key_bob);
    }

    #[test]
    fn test_serialize_deserialize() {
        let rng = &mut ark_std::test_rng();
        let (pub_key, priv_key) = Ecdh::<JubJub>::generate_keys(rng);

        let serialized_pub_key = Ecdh::<JubJub>::serialize_public_key(pub_key.clone());
        let deserialized_pub_key = Ecdh::<JubJub>::deserialize_public_key(serialized_pub_key);
        assert_eq!(pub_key, deserialized_pub_key);

        let serialized_priv_key = Ecdh::<JubJub>::serialize_private_key(priv_key.clone());
        let deserialized_priv_key = Ecdh::<JubJub>::deserialize_private_key(serialized_priv_key);
        assert_eq!(priv_key, deserialized_priv_key);
    }
}
