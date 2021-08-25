#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch::{DispatchResult}, traits::Get};
use frame_system::ensure_signed;
use sp_std::prelude::*;
use sp_std::{vec::Vec};
use sp_core::{
	H256,
};

mod verifier;

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
		pub fn store_storage_root(origin, eth_block_number: T::BlockNumber, storage_root: StorageRoot) -> DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let _ = ensure_signed(origin)?;

			// let current_block_number = <frame_system::Pallet<T>>::block_number();

			// Update storage.
			<StorageRoots<T>>::insert(eth_block_number, storage_root.clone());

			// Emit an event.
			Self::deposit_event(RawEvent::StorageRootStored(eth_block_number, storage_root));
			// Return a successful DispatchResultWithPostInfo
			Ok(())
		}

		/// Verify proof. Inputs are byte arrays.
		/// # Arguments
		///
		/// * `block_number` - Ethereum block number that the proof comes from.
		/// * `proof` - Vector of proofs, where each proof is a RLP-serialized MerkleTree-Node, starting with the storage hash node.
		/// * `key` - The storage key.
		/// * `val` - The value stored at the storage key.
		#[weight = 10_000]
		pub fn verify_proof(origin, block_number: T::BlockNumber, proof: Vec<Vec<u8>>, key: Vec<u8>, value: Vec<u8>) -> DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let _ = ensure_signed(origin)?;

			// Get storage root at block number storage.
			let storage_root = <StorageRoots<T>>::get(block_number);

			let hashed_key = verifier::keccak(&key);
			let hex_string_key = hex::encode(hashed_key);
			let _is_verified = match verifier::verify_merkle_proof(&storage_root.as_bytes().to_vec(), proof, hex_string_key, value, 0, 0) {
				true => Self::deposit_event(RawEvent::VerifyProof(true)),
				false => Self::deposit_event(RawEvent::VerifyProof(false)),
			};

			// Return a successful DispatchResultWithPostInfo
			Ok(())
		}
	}
}
