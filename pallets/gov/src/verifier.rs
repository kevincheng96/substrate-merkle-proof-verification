// TODO: Figure out if patricia_trie supports no_std.
use patricia_trie::NibbleSlice;
use rlp;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::char;

const EVEN_EXTENSION_PREFIX: char = b'0' as char;
const ODD_EXTENSION_PREFIX: char = b'1' as char;
const EVEN_LEAF_PREFIX: char = b'2' as char;
const ODD_LEAF_PREFIX: char = b'3' as char;

// TODO: Do we need to cap the size of the proof? This function runs recursively. Maybe implement it iteratively as well and compare.
pub fn verify_merkle_proof(
	expected_root: &Vec<u8>, 
	proof: Vec<Vec<u8>>, 
	key_hex_string: String, 
	expected_value: Vec<u8>, 
	key_index: usize, 
	proof_index: usize) -> bool
{
	let rlp_node = &proof[proof_index]; // RLP encoded node
	let decoded_node: Vec<Vec<u8>> = rlp::decode_list(rlp_node);

	if key_index == 0 {
		// Trie root is always a hash
		if keccak(rlp_node) != *expected_root {return false};
	} else if rlp_node.len() < 32 {
        // UNTESTED BRANCH!!!
		// If rlp(node) < 32 bytes, then the node is stored directly in the trie.
        // See function 196 in Ethereum yellow paper for node composition.
		// TODO: Not sure if correct to flatten the decoded_node bytes to enable comparison with expected_root.
		let flattened_decoded_node_bytes: Vec<u8> = decoded_node.iter().cloned().flatten().collect();
		if flattened_decoded_node_bytes != *expected_root {return false};
	} else {
		if keccak(rlp_node) != *expected_root {return false};
	}

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
			let new_expected_root = &decoded_node[nibble_index_of_next_key];
			if !new_expected_root.is_empty() {
				return verify_merkle_proof(new_expected_root, proof, key_hex_string, expected_value, key_index + 1, proof_index + 1);
			}
		}
	} 
	else if decoded_node.len() == 2 {
		// Leaf or extension node
		// Get prefix and optional nibble from the first byte
		// Need to get nibble. This is getting each byte.
		let nibble_slice = NibbleSlice::new(&decoded_node[0]);
		// First two nibbles are reserved for prefix
		let prefix = from_digit(nibble_slice.at(0) as u32, 16).unwrap();
		let nibble_after_prefix = from_digit(nibble_slice.at(1) as u32, 16).unwrap();
		let nibbles_after_first_byte = &nibble_slice.mid(2).iter().map(|x| from_digit(x as u32, 16).unwrap()).collect::<String>();
		if prefix == EVEN_LEAF_PREFIX || prefix == ODD_LEAF_PREFIX {
			// Leaf node
			let key_end: String;
			if prefix == EVEN_LEAF_PREFIX {
				// Even leaf node
				// Key end does not include first nibble after prefix because this is an even leaf node
				key_end = nibbles_after_first_byte.to_string();
			} else {
				// Odd leaf node
				// Key end includes first nibble after prefix because this is an odd leaf node
				key_end = nibble_after_prefix.to_string() + nibbles_after_first_byte;
			}
			let value: Vec<u8> = rlp::decode(&decoded_node[1]).unwrap();
			// Merkle proof is verified if the following 2 conditions are met:
			// 1. The key_end calculated from the leaf node is equals to the remaining key nibbles (based on key_index)
			// 2. The value decoded from the leaf node is the same as the expected_value
			if key_end == key_hex_string[key_index..] && expected_value == value {
				return true;
			}
		} 
		else if prefix == EVEN_EXTENSION_PREFIX || prefix == ODD_EXTENSION_PREFIX {
			// Extension node
			let shared_nibbles: String;
			if prefix == EVEN_EXTENSION_PREFIX {
				// Even extension node
				// Shared nibbles does not include first nibble after prefix because this is an even extension node
				shared_nibbles = nibbles_after_first_byte.to_string();
			} else {
				// Odd extension node
				// Shared nibbles includes first nibble after prefix because this is an odd extension node
				shared_nibbles = nibble_after_prefix.to_string() + nibbles_after_first_byte;
			}
			// Len should return number of characters since each nibble is a hexadecimal character.
			let new_key_index = key_index + shared_nibbles.len();
			if shared_nibbles == &key_hex_string[key_index..new_key_index] {
				let new_expected_root = &decoded_node[1];
				return verify_merkle_proof(new_expected_root, proof, key_hex_string, expected_value, new_key_index, proof_index + 1);
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
