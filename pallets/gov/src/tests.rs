use crate::{mock::*, Error, Event, mock};
use frame_support::{assert_noop, assert_ok};
use sp_core::{
    H256,
};
use std::convert::TryInto;

pub fn str_to_hash(hash_str: &str) -> Option<[u8; 32]> {
    if hash_str.len() == 66 && &hash_str[0..2] == "0x" {
        if let Ok(bytes) = hex::decode(&hash_str[2..66]) {
            if let Ok(eth_hash) = bytes.try_into() {
                return Some(eth_hash);
            }
        }
    }
    return None;
}

#[test]
fn stores_storage_root() {
	new_test_ext().execute_with(|| {
        let block_number: u64 = 13084960;
        let storage_root_bytes: [u8; 32] = str_to_hash("0x80c9a98e6d091d9870fa6e26f5d935dd6174a4564600e929011f682a825aa5b8").unwrap();
        let storage_root: H256 = H256(storage_root_bytes);
		// Dispatch a signed extrinsic to store storage root.
		assert_ok!(GovModule::store_storage_root(Origin::signed(1), block_number, storage_root));
		// Read pallet storage and assert an expected result.
		assert_eq!(GovModule::storage_root(block_number), storage_root);

        assert_eq!(System::events().len(), 1);

        println!("{}", GovModule::storage_root(block_number));
	});
}

#[test]

fn verifies_proof() {
	new_test_ext().execute_with(|| {
        println!("LOG: starting test");
        let block_number: u64 = 13084960;
        let storage_root_bytes: [u8; 32] = str_to_hash("0x80c9a98e6d091d9870fa6e26f5d935dd6174a4564600e929011f682a825aa5b8").unwrap();
        let storage_root: H256 = H256(storage_root_bytes);
		// Store storage root.
		assert_ok!(GovModule::store_storage_root(Origin::signed(1), block_number, storage_root));

        // Define proofs.
        let key = hex::decode("ea0d43baabaa35779c32a65010508497328024f66e5d6d3246da6d5f1196e017").unwrap();
        let value = hex::decode("029ade03ae443c0cf00000").unwrap();
        let proof = vec![
            hex::decode("f90211a0a5177e86acbc4cf377a71bb1eefc5a6fbc291bdaa24a1329fc0a7d8b1d1c1b6ea04617a3e6d77a766bf9765ea99f6551a608da5a3a92b6d3d4d77cd72c2956a691a089378dc01a14c46f4bc70b18f4f89ed999f662b10321be19f17f8a28f3ed628aa032b7aa9f61401e9dfa443173d009991ef1b11695b833b791ba955e2d201582a2a078a52bd9e3780cefaa22782c1d848d58f0c44e840be1aced5b27274e04532d44a07cc1d0bd92bf8787c419ee93c46b3081e9c327e67ca40efa12fc3340b6a57af3a0d0ed8ccb13e91933017f33bc981aa39203fdd13691c8c10ea4e1c7235b9828caa0c9aff81ec497dce19b1e11a4558b8029377bbc132ecfa78bc9f031d3b95d59c5a060258dfe689213ea4448a9a499fbad3000f28f9521a939bc1fb385b0eae28eaaa039fe2ef2f84b3e2b7c084352f2e525710232f715cdbf7a71ee17daa888e69770a0c6816a145bdb69b9e437cef45a5b8f9035b8dc53c8d9e477bd498c8f0efd21eca0c97e9000139384fde0b8c590c46e0525b73e9521dc4427fd2b47750a61dded9aa0d37b0cfb7bc7b900a79dee2d5f01e3c3fd2d788446bdccc44d44d76008c6f201a00423f3cfca18f91a52c67c6c69046fd74dadb9cf7715bfeb03ce4184d714b302a0dfa0947ef843dacb9518cbffd5d53271a3213043d88013e52620caea84123ddba054f8d0d47af761aefdce4ac8da11325d2d41fb068dc791e355933a3cac60212f80").unwrap(),
            hex::decode("f90211a01333e6382d6c303e89efd56c58d6523e41cf5b1c5f793e9969907c6772d9ae10a0afc343d852a18b7422656be334a9e3722c06a8277ef7f2c3cae86debbf3409a3a095028816b3e724ee9639c84be71d53c1898f4c81561e55e108e63abaeb3ed737a0deba0cac9c82e14f7dc90e93a1304a819cb2a304d1425da719cfb8166c31c5d0a01b1846ed768d89ceac9308c858464e78643993eeff75b9bec7e69574b1365599a0eb29499beada326c068de2109b7e463bd66490563816fe61e6d756ad83c59ec3a0bbf1eb6861321dabfb10c6ac7815cb4b33024fc9600aaaa5baf2a90944e116f1a051c65b8a9ddf67f6258d9b5988211073d6bb88848398b35901d5dbc3620da72ea00e283db6762c7e4099d1263adaebbfaedbb774e78986730c9fd9234210edfd43a0f4a9080cb4c33f75ab48b6cd58d4c0e377f457e0d56554f751d1ff5c3601cfeda09e1735497f07982c62f9a0aaf9e3202b3dad70bca9a371b0019dc99ebc7ef142a04a4c289e7c414dc4d4480efb87310600a582f33db748545b1045a09edb731c5aa09b99c3ad4c76428956477af2ecf7433ad2450bcf6e60ca793c16f66267ec41c5a03279d8fa4088ae2835d1128869efde4fac55b3f7f74b068ec244dbf99e6420bda098f20887e26eff360071b46b608f7d693bb4a8eca3f734cfae84e8a88977bec0a0e16218d34192fa20fbece5799730cdf6c0870c17bf946f7c413743e05852cf8980").unwrap(),
            hex::decode("f90211a0ac98c7316786c6533a57c8b79d460d196e21c9ea02454e70e1ccfde69965d7e3a00fe68c4d7055ba645b3d94966caf7f9c4566521b518cd4886e1b270d69dc09e0a001c22697980e8a2963dbc75d3d41fe599ee2ab59742b431547742ae7e3d72277a02e83b3c4cd7e541029235e73931a25aa96a9bcd5ee1dfc492d4167c2956b43f2a0d5c2d0732b5d73b7bdb0d253df3b7d16d22795c41ab0c12ef80b99f077f59d2ea02bb969bda9b3ff90cb5cd3dccfeb65c10796886f8d68aaafcc30a3f8b48a9769a0c93c2804966ede5ea560d9c14044d2224fda91d91884e296bfcc6e70f5b0283ea0ca9427e11890a4f01f5900305de7abe2e124f33d4db9468bb1b09621c7d755eea04fc1da0ce4f6a2a9a8b26c386011549d4f2f1b5d2ee45c049578fb1f34f6e9b0a0e4bd6053812407401a3f231e75059e0a639d73f7acdb7d3d1f51bcdcff5df140a066de3c171230a68b2b3b1355ee7e57054ebdd7208f5b6b4d3fecc89bcc78bc50a04a4304e1d8fc660c6901a9d40de4ac11b4b8eb1244349aa1344dd8f6c0cd9a8fa0c526cc5c77a725e726d1336ae57e0e9dafc55dfba1a5ba04edf9bc6bdf1b678aa07cfd650999781b5aa61b7def4734708bff88a39c427480a8cc977ff128eab694a0c5489fd491915a661eefbe2ca9908a1190e5ab82907cb60ba3f4a13f5fc1638ba0c47ab01dc431fd9e6cd1544e7dc7582eed2c6fba1fe8699736c43b5075865b6b80").unwrap(),
            hex::decode("f901f1a0f69ccfc218fb33dbc09241b3fb73d7618abd73eedfe0d0c27ec38194cc49f155a0a02657b99dbd54f6a7822ffaea4ba4639c46280c5f1fc1c2dec99fae4fa5c812a056da2d7e78f685e285d6bef4c16c96f3386d4edd8cf4daf3265134e34ae38e99a037c19426b7a66c5c6243c4ca4ba6fec137b33397e12bf077a6989deb28e6723fa0f95de4d700c36c59c35533d8d45342bea2db6f260c64bba1753812d548bc2b1ca086b4b33ce01faa10a245e4fea3b44b9d7144995f4f56349c7e98253281b6c3d6a03e4dc6648e42d122098a9ee9d9c46e900307c0c2ac7f1c741dd25e6b384bcb8ba0ca505ef73025919758cc4757c4f93d99cee37765b8a3d1c0b7028e76e0c5d9d3a025688a7ccdddfc40229945106bed07696a7882f4e1376e25f09a8061c3ded292a01eeb996259136a38e6b5eed77096c1a32372380bbf27e1b3d2177c64807c56eca08883d51217a7484c4d0673e501cc9da2046918842b26b3ef6bb0701fc2ca53b8a0a87ef4ccc71e14c850b1fd40cb5385bf939e24f02b97ad70d930347f46ed1dfca038ec805afcaffb37cc18ad86497172421f5dec53630fc3a5be68cb3e6d5df12b80a0e310547f945c43c56a886a8ae5ed81f5a456dd3282a5bfb4c5449ac279f0d54ca09726c103c0a37fa3e6838fed6697b711957028896b0736dd80fb178dcd69bed380").unwrap(),
            hex::decode("f8918080a0929cda5a139acd2d8ecb7f4bb82df6e44e7d809942017179b276cee8467f0a0680a0a08c3ce65d23544d70d19893b1b6e1308e570d3a2be2a7d23aa4fe90a4dfd0cc8080a0117d1d285a0c40e29efb210f3cbc08f87e11094f91b0b85545a6dddd1a1ecd7e808080808080a0f553c1cecdbcad6265d17a07e7a00dc05af7e6b08857d773dc92342340b81b928080").unwrap(),
            hex::decode("ec9e3b6e082fdebda47dc55282be5e6b0140a1580b3341ea097f15c13ea588728c8b029ade03ae443c0cf00000").unwrap()
        ];

        assert_ok!(GovModule::verify_proof(Origin::signed(1), block_number, proof, key, value));

        // Check that the correct event is emitted
		let expected_event = mock::Event::GovModule(Event::VerifyProof(true));

		assert_eq!(System::events()[0].event, expected_event,);

        println!("{}", GovModule::storage_root(block_number));
	});
}

// #[test]
// fn correct_error_for_none_value() {
// 	new_test_ext().execute_with(|| {
// 		// Ensure the expected error is thrown when no value is present.
// 		assert_noop!(GovModule::cause_error(Origin::signed(1)), Error::<Test>::NoneValue);
// 	});
// }
