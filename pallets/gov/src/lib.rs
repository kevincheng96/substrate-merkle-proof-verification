#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

use frame_support::{decl_module, decl_storage, decl_event, decl_error, debug, dispatch::{DispatchError, DispatchResult}, traits::Get};
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
use nibble_vec::NibbleVec;
use patricia_trie::NibbleSlice;
use rlp;

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

			let hashed_key = keccak(&key);
			let hex_string_key = hex::encode(hashed_key);
			let _is_verified = match verify_merkle_proof(&storage_root.as_bytes().to_vec(), proof, hex_string_key, value, 0, 0) {
				true => Self::deposit_event(RawEvent::VerifyProof(true)),
				false => Self::deposit_event(RawEvent::VerifyProof(false)),
			};

			// Return a successful DispatchResultWithPostInfo
			Ok(())
		}
	}
}

// TODO: Make sure the code never panics. Use unit tests to debug.
// TODO: Do we need to cap the size of the proof? This function runs recursively. Maybe implement it iteratively as well and compare.
pub fn verify_merkle_proof(expected_root: &Vec<u8>, proof: Vec<Vec<u8>>, key_hex_string: String, expected_value: Vec<u8>, key_index: usize, proof_index: usize) -> bool
{
	let node = &proof[proof_index]; // RLP encoded node
	println!("node is: ");
	println!("{:?}", node);
	println!("{:#04X?}", node);
	let decoded_node: Vec<Vec<u8>> = rlp::decode_list(node);
	println!("decoded node is: ");
	println!("{:?}", decoded_node);
	println!("{}", decoded_node.len());

	if key_index == 0 {
		// Trie root is always a hash
		assert_eq!(keccak(node), *expected_root);
	} else if node.len() < 32 {
		// If rlp < 32 bytes, then it is not hashed. This is based on 
		// UNTESTED BRANCH!!!
		// TODO: revisit this. how can vec<vec<u8>> be compared to H256???
		// assert_eq!(decoded_node, expected_root);
	} else {
		assert_eq!(keccak(node), *expected_root);
	}

	println!("Node verified for proof index: {}", proof_index);

	if decoded_node.len() == 17 {
		// Branch node
		if key_index >= key_hex_string.len() {
			// UNTESTED BRANCH!!!
			// We have finished traversing through the nibbles in the key. This should be the end of the proof.
			if decoded_node.last().unwrap().clone() == expected_value {
				return true;
			}
		}
		else {
			// Need to find the nibble value (0-15) at key_index of the key. 
			// Then read the value stored at the digit index of the decoded node. This value is the hash of the child node.
			let nibble_index_of_next_key = (key_hex_string.as_bytes()[key_index] as char).to_digit(16).unwrap() as usize;
			println!("In BRANCH");
			println!("key is {}", key_hex_string); // cd244b6e082fdebda47dc55282be5e6b0140a1580b3341ea097f15c13ea58872
			println!("key bytes is {:?}", key_hex_string.as_bytes());
			println!("index is {}", nibble_index_of_next_key);
			let new_expected_root = &decoded_node[nibble_index_of_next_key];
			if !new_expected_root.is_empty() {
				return verify_merkle_proof(new_expected_root, proof, key_hex_string, expected_value, key_index + 1, proof_index + 1);
			}
		}
	} 
	else if decoded_node.len() == 2 {
		// Leaf or extension node
		// Get prefix and optional nibble from the first byte
		println!("In EXTENSION or LEAF");
		// Need to get nibble. This is getting each byte.
		let nibble_slice = NibbleSlice::new(&decoded_node[0]);
		// TODO: CONVERT TO HEX CHAR
		// First two nibbles are reserved for prefix
		let prefix = from_digit(nibble_slice.at(0) as u32, 16).unwrap();
		let nibble_after_prefix = from_digit(nibble_slice.at(1) as u32, 16).unwrap();
		let nibbles_after_first_byte = &nibble_slice.mid(2).iter().map(|x| from_digit(x as u32, 16).unwrap()).collect::<String>();
		println!("prefix: {}, nibble after prefix: {}", prefix, nibble_after_prefix);
		// TODO: Simplify cases 2 and 3 since only one line of code is different (key_end)
		// TODO: There MUST be a better way to define inline chars then this...
		if prefix == "2".chars().next().unwrap() {
			// Even leaf node
			// Key end does not include first nibble after prefix because this is an even leaf node
			let key_end = nibbles_after_first_byte;
			println!("even leaf node key end is: {}", key_end);
			let value: Vec<u8> = rlp::decode(&decoded_node[1]).unwrap();
			println!("value is: {:?}", value);
			// Merkle proof is verified if the following 2 conditions are met:
			// 1. The key_end calculated from the leaf node is equals to the remaining key nibbles (based on key_index)
			// 2. The value decoded from the leaf node is the same as the expected_value
			if key_end == &key_hex_string[key_index..] && expected_value == value {
				println!("{}, {}", key_end, &key_hex_string[key_index..]);
				println!("PROVED!");
				return true;
			}
		} 
		else if prefix == "3".chars().next().unwrap() {
			// Odd leaf node
			// Key end includes first nibble after prefix because this is an odd leaf node
			let key_end = nibble_after_prefix.to_string() + nibbles_after_first_byte;
			println!("odd leaf node key end is: {}", key_end);
			let value: Vec<u8> = rlp::decode(&decoded_node[1]).unwrap();
			println!("value is: {:?}", value);
			// Merkle proof is verified if the following 2 conditions are met:
			// 1. The key_end calculated from the leaf node is equals to the remaining key nibbles (based on key_index)
			// 2. The value decoded from the leaf node is the same as the expected_value
			if key_end == &key_hex_string[key_index..] && expected_value == value {
				println!("{}, {}", key_end, &key_hex_string[key_index..]);
				println!("PROVED!");
				return true;
			}
		}
		else if prefix == "0".chars().next().unwrap() {
			// UNTESTED BRANCH!!!
			// Even extension node
			println!("Even extension node");
			// Shared nibbles does not include first nibble after prefix because this is an even extension node
			let shared_nibbles = nibbles_after_first_byte;
			// Len should return number of characters since each nibble is a hexadecimal character.
			let new_key_index = key_index + shared_nibbles.len();
			if shared_nibbles == &key_hex_string[key_index..new_key_index] {
				let new_expected_root = &decoded_node[1];
				return verify_merkle_proof(new_expected_root, proof, key_hex_string, expected_value, new_key_index, proof_index + 1);
				println!("PROVED!");
				return true;
			}
		}
		else if prefix == "1".chars().next().unwrap() {
			// UNTESTED BRANCH!!!
			// Odd extension node
			println!("Odd extension node");
			// Shared nibbles includes first nibble after prefix because this is an odd extension node
			let shared_nibbles = nibble_after_prefix.to_string() + nibbles_after_first_byte;
			// Len should return number of characters since each nibble is a hexadecimal character.
			let new_key_index = key_index + shared_nibbles.len();
			if shared_nibbles == &key_hex_string[key_index..new_key_index] {
				let new_expected_root = &decoded_node[1];
				return verify_merkle_proof(new_expected_root, proof, key_hex_string, expected_value, new_key_index, proof_index + 1);
				println!("PROVED!");
				return true;
			}
		}
		else {
			// UNTESTED BRANCH!!!
			// This should not be reached if the proof has the correct format
			return false;
		}
	}
	// If expected value is empty, that means we have proved the key does not exist in the trie.
	// Otherwise, the expected value was not found for a key, meaning the proof is invalid.
	return if expected_value.len() == 0 { true } else { false };
}

pub fn keccak(bytes: &[u8]) -> Vec<u8> {
	use tiny_keccak::Hasher;
	let mut hasher = tiny_keccak::Keccak::v256();
	let mut hash = [0u8; 32];
	hasher.update(bytes);
	hasher.finalize(&mut hash);
	hash.into()
}

// Taken from std::char
#[inline]
pub fn from_digit(num: u32, radix: u32) -> Option<char> {
    if radix > 36 {
        panic!("from_digit: radix is too high (maximum 36)");
    }
    if num < radix {
        let num = num as u8;
        if num < 10 { Some((b'0' + num) as char) } else { Some((b'a' + num - 10) as char) }
    } else {
        None
    }
}
