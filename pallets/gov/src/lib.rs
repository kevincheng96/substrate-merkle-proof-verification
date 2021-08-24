#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch::{DispatchError, DispatchResult}, traits::Get};
use frame_system::ensure_signed;
use sp_std::prelude::*;
use sp_std::{vec::Vec};
use sp_core::{
	H256,
	Hasher
};
use sp_runtime::print;
use sp_trie::{Layout};
use codec::{Decode, Encode};
use trie_db::{proof::{verify_proof, VerifyError}, TrieLayout, TrieConfiguration, TrieHash};
use hash256_std_hasher::Hash256StdHasher;
use tiny_keccak;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// Define types
// #[derive(Copy, Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug, Types)]
// pub struct StorageRoot {
// }
// Storage root stored as bytes.
// TODO: Explore making this sp_core::Bytes or Vec<u8>
pub type StorageRoot = H256;

// #[derive(Default)]
// /// substrate trie layout
// pub struct Layout<H>(sp_std::marker::PhantomData<H>);

/// Concrete `Hasher` impl for the Keccak-256 hash
#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeccakHasher;

impl Hasher for KeccakHasher {
	type Out = H256;

	type StdHasher = Hash256StdHasher;

	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		use tiny_keccak::Hasher;
		
		let mut keccak = tiny_keccak::Keccak::v256();
		keccak.update(x);
		let mut out = [0u8; 32];
		keccak.finalize(&mut out);
		H256::from_slice(&out)
	}
}

/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Config: frame_system::Config {
	/// Because this pallet emits events, it depends on the runtime's definition of an event.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
}

// The pallet's runtime storage items.
// https://substrate.dev/docs/en/knowledgebase/runtime/storage
decl_storage! {
	// A unique name is used to ensure that the pallet's storage items are isolated.
	// This name may be updated, but each pallet in the runtime must use a unique name.
	// ---------------------------------vvvvvvvvvvvvvv
	trait Store for Module<T: Config> as GovModule {
		// Learn more about declaring storage items:
		// https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
		pub StorageRoots get(fn storage_root): map hasher(blake2_128_concat) T::BlockNumber => StorageRoot;
	}
}

// Pallets use events to inform users when important changes are made.
// https://substrate.dev/docs/en/knowledgebase/runtime/events
decl_event!(
	pub enum Event<T> where BlockNumber = <T as frame_system::Config>::BlockNumber {
		/// Storage root stored.
		StorageRootStored(BlockNumber, StorageRoot),
		/// True or false for proof result.
		VerifyProof(bool),
	}
);

// Errors inform users that something went wrong.
decl_error! {
	pub enum Error for Module<T: Config> {
		/// Error names should be descriptive.
		NoneValue,
	}
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		// Errors must be initialized if they are used by the pallet.
		type Error = Error<T>;

		// Events must be initialized if they are used by the pallet.
		fn deposit_event() = default;

		/// An example dispatchable that takes a singles value as a parameter, writes the value to
		/// storage and emits an event. This function must be dispatched by a signed extrinsic.
		#[weight = 10_000 + T::DbWeight::get().writes(1)]
		pub fn store_storage_root(origin, block_number: T::BlockNumber, storage_root: StorageRoot) -> DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let _ = ensure_signed(origin)?;

			// let current_block_number = <frame_system::Pallet<T>>::block_number();

			// Update storage.
			// TODO: Replace with block number of Ethereum chain.
			<StorageRoots<T>>::insert(block_number, storage_root.clone());

			// Emit an event.
			Self::deposit_event(RawEvent::StorageRootStored(block_number, storage_root));
			// Return a successful DispatchResultWithPostInfo
			Ok(())
		}

		/// Verify proof. Inputs are Hex encoded.
		/// # Arguments
		///
		/// * `name` - A string slice that holds the name of the person
		/// * `block_number` - Ethereum block number that the proof comes from.
		/// * `proof` - 
		/// * `key` - Key. BYTES of hex
		/// * `val` - Value. BYTES of hex
		/// 
		/// TODO
		#[weight = 10_000]
		pub fn verify_proof(origin, block_number: T::BlockNumber, proof: Vec<Vec<u8>>, key: Vec<u8>, value: Vec<u8>) -> DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let _ = ensure_signed(origin)?;

			// Get storage root at block number storage.
			let storage_root = <StorageRoots<T>>::get(block_number);

			let items = [(key, Some(value))];

			let result = verify_trie_proof::<Layout<KeccakHasher>, _, _, Vec<u8>>(&storage_root, &proof, &items).map_err(|e| {
				print("Proof not verified!");
				// TRY TO PRINT OUT ERROR MESSAGE
				Self::deposit_event(RawEvent::VerifyProof(false));
				return DispatchError::Other("Verification error!"); 
			});

			print("Proof verified!");
			Self::deposit_event(RawEvent::VerifyProof(true));

			// Return a successful DispatchResultWithPostInfo
			Ok(())
		}
	}
}

/// Verify a set of key-value pairs against a trie root and a proof.
///
/// Checks a set of keys with optional values for inclusion in the proof that was generated by
/// `generate_trie_proof`.
/// If the value in the pair is supplied (`(key, Some(value))`), this key-value pair will be
/// checked for inclusion in the proof.
/// If the value is omitted (`(key, None)`), this key will be checked for non-inclusion in the
/// proof.
pub fn verify_trie_proof<'a, L: TrieConfiguration, I, K, V>(
	root: &TrieHash<L>,
	proof: &[Vec<u8>],
	items: I,
) -> Result<(), VerifyError<TrieHash<L>, sp_trie::Error>>
where
	I: IntoIterator<Item = &'a (K, Option<V>)>,
	K: 'a + AsRef<[u8]>,
	V: 'a + AsRef<[u8]>,
{
	verify_proof::<Layout<L::Hash>, _, _, _>(root, proof, items)
}
