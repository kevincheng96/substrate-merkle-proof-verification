#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use trie_db::{proof, TrieLayout};

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://substrate.dev/docs/en/knowledgebase/runtime/frame>
pub use pallet::*;

// #[cfg(test)]
// mod mock;

// #[cfg(test)]
// mod tests;

// #[cfg(feature = "runtime-benchmarks")]
// mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
	use frame_system::pallet_prelude::*;
	use sp_std::{vec::Vec};

	/// Define types
	// #[derive(Copy, Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug, Types)]
	// pub struct StorageRoot {
	// }
	// Storage root stored as bytes.
	pub type StorageRoot = Vec<u8>;

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	// The pallet's runtime storage items.
	#[pallet::storage]
	#[pallet::getter(fn storage_root)]
	// Byte representation of a storage root at a specific block number.
	pub type StorageRoots<T: Config> = StorageMap<_, Blake2_128Concat, T::BlockNumber, StorageRoot, ValueQuery>;

	// Pallets use events to inform users when important changes are made.
	// https://substrate.dev/docs/en/knowledgebase/runtime/events
	#[pallet::event]
	#[pallet::metadata(T::AccountId = "AccountId")]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Storage root stored.
		StorageRootStored(T::BlockNumber, StorageRoot),
		/// True or false for proof result.
		VerifyProof(bool),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// Error names should be descriptive.
		NoneValue,
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// An example dispatchable that takes a singles value as a parameter, writes the value to
		/// storage and emits an event. This function must be dispatched by a signed extrinsic.
		#[pallet::weight(10_000 + T::DbWeight::get().writes(1))]
		pub fn store_storage_root(origin: OriginFor<T>, storage_root: StorageRoot) -> DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let _ = ensure_signed(origin)?;

			let current_block_number = <frame_system::Pallet<T>>::block_number();

			// Update storage.
			<StorageRoots<T>>::insert(current_block_number, storage_root.clone());

			// Emit an event.
			Self::deposit_event(Event::StorageRootStored(current_block_number, storage_root));
			// Return a successful DispatchResultWithPostInfo
			Ok(())
		}

		/// Verify proof.
		/// TODO
		#[pallet::weight(10_000)]
		pub fn verify_proof(origin: OriginFor<T>, storage_root: StorageRoot) -> DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let _ = ensure_signed(origin)?;

			let current_block_number = <frame_system::Pallet<T>>::block_number();

			// Update storage.
			<StorageRoots<T>>::insert(current_block_number, storage_root.clone());

			// Emit an event.
			Self::deposit_event(Event::StorageRootStored(current_block_number, storage_root));
			// Return a successful DispatchResultWithPostInfo
			Ok(())
		}
	}
}
