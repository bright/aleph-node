use ink::env::Environment;

/// ink!'s chain extension counterpart.
///
/// Chain extension methods can be called by using [`BabyLiminalExtension`](crate::BabyLiminalExtension) trait.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
#[obce::ink_lang::extension]
pub struct Extension;

impl crate::BabyLiminalExtension for Extension {}

/// All default, except `ChainExtension`, which is set to `BabyLiminalExtension`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum BabyLiminalEnvironment {}

impl Environment for BabyLiminalEnvironment {
    const MAX_EVENT_TOPICS: usize = <ink::env::DefaultEnvironment as Environment>::MAX_EVENT_TOPICS;

    type AccountId = <ink::env::DefaultEnvironment as Environment>::AccountId;
    type Balance = <ink::env::DefaultEnvironment as Environment>::Balance;
    type Hash = <ink::env::DefaultEnvironment as Environment>::Hash;
    type Timestamp = <ink::env::DefaultEnvironment as Environment>::Timestamp;
    type BlockNumber = <ink::env::DefaultEnvironment as Environment>::BlockNumber;

    type ChainExtension = Extension;
}

#[cfg(test)]
pub mod mock_test {

    use crate::Vec;
    use crate::{AccountId32, BabyLiminalError, VerificationKeyIdentifier};

    #[derive(Clone, Default)]
    pub struct VerifiedMock;

    #[obce::mock]
    impl crate::BabyLiminalExtension for () {
        fn store_key(
            &mut self,
            _: AccountId32,
            _: VerificationKeyIdentifier,
            _: Vec<u8>,
        ) -> Result<(), BabyLiminalError> {
            Ok(())
        }

        fn verify(
            &mut self,
            _: VerificationKeyIdentifier,
            _: Vec<u8>,
            _: Vec<u8>,
        ) -> Result<(), BabyLiminalError> {
            Ok(())
        }
    }
}
