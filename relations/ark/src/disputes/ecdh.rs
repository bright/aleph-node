use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{bytes::ToBytes, fields::PrimeField, UniformRand};
use ark_std::{hash::Hash, marker::PhantomData, rand::Rng};

/// A simple trait for generating a pub/priv keys and creating an ECDH shred key.
pub trait EcdhScheme {
    type PublicKey: ToBytes + Hash + Eq + Clone + Default + Send + Sync;
    type PrivateKey: ToBytes + Clone + Default;
    type SharedKey: ToBytes + Hash + Eq + Clone + Default + Send + Sync;

    /// Generate a pair of public and private keys.
    fn generate_keys<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::PrivateKey);
    /// Create a shared key, based on public and private key.
    fn make_shared_key(
        public_key: Self::PublicKey,
        private_key: Self::PrivateKey,
    ) -> Self::SharedKey;
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ecdh() {
        use ark_ed_on_bls12_381::EdwardsProjective as JubJub;

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
}
