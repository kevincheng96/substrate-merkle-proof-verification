use crate::{mock::*, Error, Event, RawEvent, mock};
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

       // Check that the correct event is emitted
       let expected_event = mock::Event::pallet_gov(RawEvent::StorageRootStored(block_number, storage_root));
       assert_eq!(System::events()[0].event, expected_event,);

        println!("{}", GovModule::storage_root(block_number));
	});
}

#[test]
fn verifies_proof_with_odd_leaf_node() {
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
		let expected_event = mock::Event::pallet_gov(RawEvent::VerifyProof(true));
		assert_eq!(System::events()[1].event, expected_event,);

        println!("{}", GovModule::storage_root(block_number));
	});
}

// TODO: This fails and causes panic
#[test]
fn invalidates_proof_with_odd_leaf_node() {
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
            // Last hexchar changed from 0 to 3
            hex::decode("ec9e3b6e082fdebda47dc55282be5e6b0140a1580b3341ea097f15c13ea588728c8b029ade03ae443c0cf00003").unwrap()
        ];

        assert_ok!(GovModule::verify_proof(Origin::signed(1), block_number, proof, key, value));

        // Check that the correct event is emitted
		let expected_event = mock::Event::pallet_gov(RawEvent::VerifyProof(true));
		assert_eq!(System::events()[1].event, expected_event,);

        println!("{}", GovModule::storage_root(block_number));
	});
}

#[test]
fn verifies_proof_with_even_leaf_node() {
	new_test_ext().execute_with(|| {
        println!("LOG: starting test");
        let block_number: u64 = 13096010;
        let storage_root_bytes: [u8; 32] = str_to_hash("0x4931119b41f0d0047162d6ceb4bd6f73e8932c5ad7360d39d6febd033ecc1ac7").unwrap();
        let storage_root: H256 = H256(storage_root_bytes);
		// Store storage root.
		assert_ok!(GovModule::store_storage_root(Origin::signed(1), block_number, storage_root));

        // Define proofs.
        let key = hex::decode("9b4ccb6f3f5a675c4a585294f5d37a4345ced1f2eae2c26627625fca2715f743").unwrap();
        let value = hex::decode("02af").unwrap();
        let proof = vec![
            hex::decode("f90211a03b745000fb00ca23183789333a8272472c550764ab595787c6524a473811ed7ba0c41b7c80e09609692f498d0d61817cecb0dc4c19f0c0f29cbdced4d8aa87314da0f14c3b8aa9307f5ca4aa9c96dc9697917b28eac104edf9796bfc9d2e65fe05a9a0fa809a837076e00584fb36feeaf58b2d886dd8e4fe25291a191e5d62e685a5c6a0fe9ef95e7371c703873eea9577631225ed77abdc601e7dbc6ec143c108bd16bfa0a5d4941a3995f9d9d7b692a501500705bc4f97ae1f981be523369aafd9e0781ca0605a8ae9187e651b107f25ffadafac0f802b0a33794bf1d9b5355500f765d007a0ac72d7acd420411450e9fc9a4255c9b97664bb0dff4fbd5d17b7493f367d7c27a0ae86115d2efc61ca5a5536a72d1f4378a596a4e4c55ca5766473585ed664cc58a0c601b7d02f0b8446b4e4312095f6e0f302ef5210f7b71c4801d7c512fed05577a01cca3ac353b215c11a1bb7022695035cfce1b1e23c5053e224e51aab674cf886a05677ee57f30bd4b15708f3a32e65cb1b11b68bb9fa124a5519f04c88b3cd6ce4a0c2b6a7d6d173ddd9107c0be214774fe02553b54be6e05641e5dab9bfed13d7eba0a92621772dde318c6aa779bc6a27baeeb99a745fbd8901cf31d5f782d51e2bb6a066a2f0510b2abd6dadeee4687cfdb09ebbfc990ac006224e6de77073da2e13d9a021940abac39faa3ec0da80c5ffacc74508a079a75a5c79e8eb88d0062f30a66d80").unwrap(),
            hex::decode("f90211a08fa78e68433171906c18d7ca777d262f5302a6fbafc5f641a7f2de37b7e2d1c8a0c90a38798d19996145b5091c966f869f8ec2436065633460c5bfac86f63fa9c3a01f4decc431635a64c1c1231bd146787c2721bbfdf15a9a7aa23de61645bd1e98a0682d7b683307bab8d6f3bdd24de0e126e769f4bc04c608fb4c4582b94b4ed265a0504df599a6a6247a753c42549effe198024f00db26dda174b85c35ee1388717fa097cbf292ee9fa9f249224232acea73c7f7f1bc1250962ea218fe3dc6f0ecbc96a05b884dffe6459ec70066ce80acc7f6e41daa94b4430e62587ba408634000a2c6a05c53370b92e4a9f5e46a45da77a00f2da7e3d002a5fab3b02913315f9598c848a06d9414ec3ed9f2344b821542feb93e32d6bb2a9c2d60cc064ccf3cf7be946662a006beb92c2e24d2d8ec20bce561a39c1e0680c7831d45e224173c98c90740cceda0ed85b8808a886716a092969a9d2efe648a03c583ed2818e11ba59e2f3eee1b1da0cec08ff3011a21e04eb01df871712c69593453f9ba775951414906ce1f621464a047d3cc74b405b9a2fa03b7eda6ae0cf0b2599c36ee94b55e919095ed6bba60c1a04b3d3c960a72ed8517d61f9bea47d1e581d15b84408fe18f3985a51a74498172a03f0fccba4bbf52915a0fedf60a113c10982f096b7bfe1145f229739478223460a09d292fb147c09f87e95f056cc6b94fec8ceab854ed6b84299871c300b9ae08b980").unwrap(),
            hex::decode("f90211a0252695736e59b8866457d51987af51eecad392aadc4e8441fd959bd300760d33a087ebfa5e9a72e94daba6c6c9cc6820e7bf8bd53f336db73bdfb8f33374e2f949a0bf4ac4058b6400261f070455768ee857d8b4c22ef008fe1a0fa0f13b91e6489ea066ef688bd6db926f9a4d1d4edabacc0c812daface6ab7779acf6e795f2ead32ba017afcdf4b76a00ca27c9975506a03362718c2763536621c625e3060222f959c6a0baa9eea6bc017324300ef5274119d0b11cb9edd7cdaca30da0ba42ec137b2c76a03f0225124e4335ede077209c415735d5878f5dffcbbbabfe373ca986c9b64dbfa09a9fd42416ea8c4ec6e6872a8fadbf8ad949874e72c68a3c55fd54fa21ff523ba0ec32b046988d1e5ea68b4bd77341a0982a0653b4db0ef2030eb37a4fd9036eaaa0f4b4e83b923c7e61628c7bfaaaac59d9780791166b8d6dd985d4bc9ced823541a09709ffd81aeb41b7fc3babe8c1da0efc7918dbdd0f6104bdb8d779e452c27482a02cb74297f79b3874a504deb521dc43c76aedfb63229426788b0f369e1c6b6b96a0f14a3344192015d7dfc6e503cad2296f6c8abe1bf5041853a3620d1e62761e1da0228a49ec0ca81862251eb06093553851c83e3ac6f2850f7b2342c8283573fa9ca0f17ba9305d87fdb3f6b2a5f117c426b089b339dde843fa0131da9d354bafd3d7a0d7d371f3d3d4bdbd2f96098fb82d8bd7106266b704e009ab5de7d13b1dfbf55780").unwrap(),
            hex::decode("f901f1a0aeb50e41e5419e976af5f4bf44f6f1c04a4e86fdd7fec2b634275d079276deeaa0c9c0921069518c1a41755f63032de5510299208e2773f7580fad02384a392f37a0a1e5ef204b0ed07ef50375ab79a71464eb57433424ef62ac915486becdd64ee4a0d69ba4c8b51dc9938b5bfc7ff2a49a443a3b87b198629d8513e18858c3773838a075159777c5cce79a06ce3842c1ebf235ccd2154edaeb666d915854d88425de4da00fc3af995144f11894b5ec22b3e73d2304bf0ce5dd97e80393ad0259bc955b8ea031cb495ff9ba66102d08a4582224613fccfeb7f143e4fb8782952da40883d5fca0c1c9612c8031ad016c90e7571917cecb31036aaa63456343d599afea57aa8a24a0cc18216ed8667e4b00d8b45284f530afd9725d028c8341f9ef9eb98b83ce3ddb80a0e8848985605b3888b6ddda0dcfbb28348f0b54413ebb527646708f4a2fccc5f5a08c2d772fc7a5cec8eba7b35d68ba1d37247607989a2e7b1dff4773292435e949a063979cdcb3e9b6cdc1862f22b17117b119c2389ce5d7dc6cf1226deca0ded73ea001fd041caea3f159f923729fd9996ae5d89cae2b8f848802cd73d60d39f4a30aa080d50a8106e7041643dfde33d48c3e6246f1f9d3938b91f5d44d6498e4ab56e5a0c2aa0e69dce7aed9360a02d8f5aba7c41e78bee976c63f1bf71f18a2a62fdd7380").unwrap(),
            hex::decode("f8b18080a054114914c94cc75bf5dcb15ddb0431ca33a4070a901c242a7f35ed06b3e3fe8480808080a0f08a5f5c54163c07dd8bd6d2723837f161fff16a97fdfed12a2dc55b9bd8823680a0f20163694274a056c430e042e603e6dd1b8efd9b04c01ba93bc4734c6f816aa9a0048fa1cac19427781074054cbafd1d91115f6472cb084bc12c4d5c47267b11138080a034222c93dbfbf699a57301778bf950f3cee3bbd40f423fe9baeefa536a4a681c808080").unwrap(),
            hex::decode("f871a0b9ebfbd5b07546530f7eb3b663cd48706bb6f4779af50a51e62f963f83f8dda280808080a08f1a8d46804e18b72bcadfacfc59e0a5e4c12aea351f805505f08d2a264b8cb280a058b4bdeb6da0355607102b6db76a7bf40b21bbac273911bbfa13f3320502b201808080808080808080").unwrap(),
            hex::decode("e39e20724734010729573fdf89712a74c5974a6ac5cc0c4f685bb84cd96f9c01838202af").unwrap(),
        ];

        assert_ok!(GovModule::verify_proof(Origin::signed(1), block_number, proof, key, value));

        // Check that the correct event is emitted
		let expected_event = mock::Event::pallet_gov(RawEvent::VerifyProof(true));
		assert_eq!(System::events()[1].event, expected_event,);

        println!("{}", GovModule::storage_root(block_number));
	});
}

#[test]
fn verifies_proof_with_odd_extension_node() {
	new_test_ext().execute_with(|| {
        // Address 0x0119d800835BE09030d0ebF072c0A8C381a70157
        println!("LOG: starting test");
        let block_number: u64 = 13096010;
        let storage_root_bytes: [u8; 32] = str_to_hash("0x8a4002a7af8c1c1eb2cf68f6fcc289f27cbc36740aa87d899d1e5d420312abfe").unwrap();
        let storage_root: H256 = H256(storage_root_bytes);
		// Store storage root.
		assert_ok!(GovModule::store_storage_root(Origin::signed(1), block_number, storage_root));

        // Define proofs.
        let key = hex::decode("5b452282425c47cf6c2083692ed3cabf7c8c94446c1e476a19e577040d1752c9").unwrap();
        let value = hex::decode("6f8e8d50157800").unwrap();
        let proof = vec![
            hex::decode("f90211a0805b212b8029e3c71348a727dc816334b4cc9913dd4bc3605e93209d43fb4883a0447612ad58c7484f2f0ca3ed80c045a66110e1d814479d384b8543c472f9260ca0a2f0b4f5d2e8713de421dc0408567cb637deba8c3530aa838727e87c13ea516ea0f2c71d708c3ce7d796d386cdc81b6e0f5f47ca82493109e6f731e50214badfb8a0133a3aa4cd17e536deb4ac1150a12607471c310b11d13d5166bcaa6d52f4faa6a0545f0a186e82d26b0560b7389328379c223021b8cc4fad2f37316be6d6833a96a08a8b392456fe8c9a39d68cd267c00b350310b5d7b0dc43dc46c90fe7748d44f3a01b451c576f174a13ddd7ac8e96a57fa324074284f1ab95dca66295eef9f17999a0fe860d6ccb7c4decb3da7ab7d04ece1e5e95882823087cfd6612efa5dd16cba0a04307c94730e5c783622952447a97993ae78d823f6b03ac64ead7216c185fb902a0ebef65f3fa64244027fad029bc015e34fee973c1fe2e2699374a06501eb7e3afa0e671bef90d36b04c5754e7944053d831d362e3f5aeb5a07a4a5b67892ba7ed6aa0056e3a70720da990e8781a8e31834bc67c0f6fb70a8c5c12a3a3f64d16f5cd81a07e161e648f1a15b62bb0626e1762d195e24c37cb5592e1abdff6df2a8a3eae17a0ee268e8221f20d60b829885cd13d264951004a8c8f0a0496bbf848861d52fd85a030f1f766287d4af74a59240f4746a94012f491d726222f9a89e1a4600a41ff0380").unwrap(),
            hex::decode("f90211a0e9d48302e67b0c80c67fb1928b2c13e157295e7d0b9af2f5ed651d58bca63f74a03d7dc222c46746b573ad70e3a0b21575ef9680bf5e73aedaab778eadb35bea04a09c75018ca6b5b5bd3bee4c0707c9c7af60e2305b681f4380ea90674b8a482673a08a32eed2801672b3b3f6a4c9dcd4254e9e4907620e0662df6ca0c5ba74373c66a09e32160423bd1d8af4f46cbe6519c98a159dd8e3cbf62366902f00cfb20ee6efa01e511996187d046ea32625caf2e4454a470a4c949c93c5062d3649e323c41f67a02d318d0987f861575303342c466928b994c75cf347a51e805cfa3cf703dd17f6a0801cf06262a7d7891c679a0b6feffab1e14e25434cdec327f80f2611f6b5d68ba047e1874eef0c3a0d18e26dd502f311fbe7e0b0c4114d0199f750aaf3149c2684a094632d23088c3b8e8d9637666841fd25f85ee0172395b061207d97da862c7bd1a07099c1d8658ae057564959b51ff516e0dd2c6dc4e5925ecd34f3a66b3349ead1a076030f6c155edab8b24987d820aaa6cd62264bdff6d1c5baafed525c6823d407a0a6f8fd5895e06ee3157949502c71c5e383803d0e85118102b6d6a36c460dd10aa0c5fe030dca4e2b487f263705815c518f748b6bb3910fffef065c7c1d94187e25a0d6f40f5e770cce8f067849f993750b411cc66eddc3b5baa0af43a1d5da0401a9a0fcafb875f3ce84c2ddc4b0ff3bce43fc193ef1bb65989b91aab32f32fc5af7a480").unwrap(),
            hex::decode("f90211a0a41152933a09bb86b4125582b36ee34f6b2702b4ea4f9c04ccdae302a78705e3a010bb3aa00c13d39568e17bfeb4d0991e4e06ed67cac1c9a008eba7314d9ff992a0d7fc44cb5dab154c7b09d12a0006771c164123f07cf691d4c7f162b20c341aeba0a1b8b18bb4596152881b2ea9732d047162a6a52c132d7988c2090c6b047b84aaa01c5947fba279910184305c4fe5eb84404487b673096d119a3ec3d2f1e337797ca01298dec2d80877dce1d6f44a040e87154c3746d6a63804009a9bf07d97b98bdfa05a66d8877f3fb6ff78793d6bbfa0474fd4bdd23aa67ed9bebd420f9d00877933a0756773cb2404a87cc50a116d53d159aa28682058da146f3bb851d5d06ba2bba8a0adfb2c3a89e8faa3931bffaf2974343667571ac379e099c95ff4fb50258ff18ea00d5d5354d28aa0b5cf3179a0d55b7d4078652c203d4f618d51fd2af7bd833625a0f6a8c3718a9c0da58f7a942210478854a29df4c6c8e1543b79595d5376130d19a046cb889934cd6ec9f23405446f8a2a13321d2e03e810b0fe7fb74d5ce6ae2183a03a618bb5376025a193c41d782614274ebda344fecc007dd6ae292c9a8340aab1a0082880186488dd5741d1935cf01fa3c00e41f4d1ba46decbcf3b1f0e2ccf755da00c62c3f6a36abbac49011a8a27a0f7e2bb9a50f2e683ffdfddd1444d5acc4fe3a0b9abe4cc6a34039cdda0a216acd1458b6e11c8a7ae53d30c838062bc9de3288580").unwrap(),
            hex::decode("f901f1a08f5476e5c3635f4af73342146d0225492c72eb88473b9fc32b52c5c5aba0157aa04fc1d0e96876e2c5d8b93c5908cadb1c727638544b213cc6b7119534f2e98ad1a01bb29259742b88df67fdf333ce9bd3bd877e462902a1ab9f3d5ee3bc5b44a933a0bced217bf3f70d5b13f805bc17017089fcca499777353f010a1a1dc644280df1a0742b9fc985a7121daf47c4dfb24508381e14200ce6f749c282bacfcc0293ee49a0565c76c7ced42adf2f63e9294809040e9fa1a189b60966848d43f8686451b361a0f8e10c215217943d05382d366c8671f4bf757ef62ce6488afc1e76d053964a15a0afd21ae55afc7ea3e2a02bc93acd13562db7dc9fd9d904b9f3ad337d38b3b40da0ede98f42517090b0e9e927571873fc2c6bbf89da8eef413c9e28338df046bb84a0524e10e3f62c80118705c319e25cd5a522844583160573951456f52b9302e092a0bb985326230c7fbd01da81d1c448e416116c93180bf0890bbc433c6e27466560a076cbea73192c8a5331dafc494cea9d6cfe4960e34108c43555a8dec079bd789680a0643b5bfdcf5b0b0456cacde455ef0fbb5241f8c0488af233901c28596f6e4619a05e3176f81ae537b64c53cad3ebceabe1bf8525ae679361e9b4e67516156314c8a0c64588f85fca8b7b7519e2af7703adc11deeb15555d46b5c06d9efb40a397bc380").unwrap(),
            hex::decode("f8b1a03edbe6055871c480d55ca6f3635ff1b8f13f1291e6d09cc034156c323a52994e80a03a381277c5bdec7231d2449a543316bdafa6bda7515d3f58fdf1c89f2b448160808080808080a0ebf4bcf7b1f5611b2c945cb1cbddf4bf4acf6a46d0a0c646305e914c5f5ca08e80a0f13637aee3a838cabf0fd78c3fd28c4cbc0b8c83a2b518f273e988f8be2b1ea18080a005e5378e54feb4ac51a7048954c7b3d7954726a9ca64ad1881a2f8ccd43a50e18080").unwrap(),
            hex::decode("e21aa039bff714c382d991cb3fab55d691a929fcafca387402ff37ac8f2efc81ed16f8").unwrap(),
            hex::decode("f8518080a0f8335b728b1c0eb4b46fdaac0e2fac1a77b8e9a076d89773b6e3dbbc9fe50cb980a07480ad3ad85ccb039c9af27db916054f2dc240be1557170001c2c7eb529c6e2d808080808080808080808080").unwrap(),
            hex::decode("e79d31fefb90bf7a083b865ca5e65fd82a6e2dd2470cc047cc6b7a942e4dcc88876f8e8d50157800").unwrap(),
        ];

        assert_ok!(GovModule::verify_proof(Origin::signed(1), block_number, proof, key, value));

        // Check that the correct event is emitted
		let expected_event = mock::Event::pallet_gov(RawEvent::VerifyProof(true));
		assert_eq!(System::events()[1].event, expected_event,);

        println!("{}", GovModule::storage_root(block_number));
	});
}

#[test]
fn verifies_proof_with_even_extension_node() {
	new_test_ext().execute_with(|| {
        // Address 0x02a9A4dA25996623bf2db451a22D70CF7b46Fdb0
        println!("LOG: starting test");
        let block_number: u64 = 13096010;
        let storage_root_bytes: [u8; 32] = str_to_hash("0xd73c7e14e051e1acc08e023cd30a08409520de8932edd335a91426880726834c").unwrap();
        let storage_root: H256 = H256(storage_root_bytes);
		// Store storage root.
		assert_ok!(GovModule::store_storage_root(Origin::signed(1), block_number, storage_root));

        // Define proofs.
        let key = hex::decode("d0c9cfaba4a6f4ab991bd5930bfdeae91e42666f5cdf1f16da02ab8afa9f9132").unwrap();
        let value = hex::decode("883a11f9a9d59c").unwrap();
        let proof = vec![
            hex::decode("f90211a07bea44ba5457a53a49ce2be0a0b8f46f139afae100386298c579602878511eada0208feb5ab65be53aedd2a7ce026a83e8019dba6cbe14a1f6d2a3ce6d8ea00006a06bed3fd58bb8f2c5c3f1a37c7d70a50aa0b4821364bc1430cd9723ae950f3ae1a057f57af7745b6de10e316c361064654034de882a7d4f0ce5ab68563b6977cd32a036eca291fd62781fd42887dd74a4b5d96a30c81d556b364958d5483d13aaacafa0ecc69daf278a748d3068bf81f43119f9df132852fec6cde31b2102b08a12d70da0ce82e54c3c16981a3f1d1d7d1f254d3f61b3f9e6be98dd88ce8071b7a91175e6a02a85f0d982a85689997ad7c2d38727338e01d28408f88562392ab05e29304968a0967ce97ce67a7b3e001d075c52a620d2f9b03ad1b6c61388fea926be331da23fa08a121fa938fb89c54d58d9901208d2752632cb76199bb19851ebd40b8a4b9dc5a047d038c69ff4355460e587dfea1119c8d0f8bdc3212b10054b3065e276e34ef9a0173ff5d59ec2c5a7027dcf063bb6005c78a91bb1427dc7c40554be5dee53a348a078a0f99a990040a3f8df2cb32c2005c77bfa99ed3a19d2af71366d8d0849a552a06c7552ca5f4799b1a375f709a7242cd9964ec5e3152f2c34e71e17e57b45869ca04efc30c8853df44514bdf4093c00a97d9a6966508a91214d5d4257726717bad8a0ffc9224005f70f57ecbaed4cd8b37611714dc08258c3ed88d0f3da86b9e8400880").unwrap(),
            hex::decode("f90211a01a575e0fda6d33f932dcb5d5675a4cd7fca92a5a31ed5dd0c19fe07b89e8563ca048abcf1e79c14302f7bec6b6ea3e4f3d1e03e983e7499d74f514bcac56592194a0411b3e914d6db85af14a153fab15c856550a5862f003e2da81f8c0b0f66c7e5ba01b2a151a4dc713c2c669e706ec1db426535af87fcf112731213984314ede7306a0e716b1aaea1cd6810b1a2a67083373fa08730845bb789a84ac540fc62cc17ad2a09f220244402b76bc24eb41da7050884613cb472a818a1e238cb9d4e9b0da206ca006777127cba411f3faf339517a0611874fff7b79ea18280a6dbbfab73dab4918a080cbcc5478955ffff42a877497d8dfa9e406f02a7adcc09a2b44908f14557c10a0d68502e3706274437531d03d5df9b2056085000584194b57ae2c4a32b77b14c6a05e827a764caee00835b42cfb3e85909b77019ef63ea325cfdd0a797eddf72cc1a0011257fe678328dd0a497cf02fc138260d6be69fa846ce1ba5ab774958cd0235a0096d792ccbf509728a40fd3e4460fc6824f35d3a7ed58501588132792c57561ba01e9ab9660c4a8d4dcf262704e577af6bce1f6fd69828863589f45a8340aa4618a07e20932530a749f9d09b386f8b4e0627f8258d9501b7cc91f3bb9d9c024facfba0eb0b0edd4bc577be851db194ce992e99c583a40f405525f15c74965928773fc0a010e81d3cf4a4de8588fa67976223e396e56577a1802899c2bb5c5a8f55125b5c80").unwrap(),
            hex::decode("f90211a0775dc0640777c893827d1c431ae949097582a0098eb096f6d4407c7d5d67e7cfa08556bacb6f5e30f62c6b5e1e10cd8e47467c713526ace43dd716c54050ed2aa6a0604f6a8cd7034dc81c9471a8942c55e634dc6732a1333ffee8b0f3039fb2f09fa0e3c7f9f27fdc77fbbcccd1be019f1905adc52b46dd855eaa7c3606309fe3d7eba073925dadcf8ec98c58c81c8080d254b67d8ad98307dcfd831cd1ee42c737aa9ba03d132d7243c236d9ac0a94385b0c5de3b9fb21d66142979df26c443df4dcb611a0a8e8db5db34100445b773387b03b871c9c645ee137112f306e0e7b42e294d5d5a038aead621a18334be9bd3a5711d4f50b3a82ed577bdd188078a658f291573d40a086fef972a499c633049fd3caef70d1d2925e9067f9e1c86023e2722b4eeb425aa0ae57b94e579f9f0580148d0113c187295bf48ad755cdc3bb9788d1775b63a0f8a0612c2eb46f75f647304331a08733bca58c539d0c5043a09df62c6f180b664c75a01a93a9f75594f856119b8177753897b97ac30cea7436d7baecf0494b83163702a07c80c981e01af48af6c1ad94840776268fc4f9bffc3b44ec8ca46e89bd952681a072755825b3c19aa39468da7e46a475dd0acd1a4572e95db0bcc62bcd553cea8da0fa17357b109db48d4f44fab679a55f0f2e0b88e31b37e01a0a563f89b390f7c4a029fc72bf625cc19874177a5197d82470182b24d1310b1d8c5efbf6ab7f3ac58880").unwrap(),
            hex::decode("f90211a07521efe7e5ca0d4700010966f1bee69e0181351852d3149df29de1d9ca9c1eb8a0cd4af3f91a7bf98e6e65a485907ed6fb858b1f3b90fa5332f91451544f344fe4a05f04ba3e356674c8f743c10c2893dd4947060a3e7876e5aad957ccc8ca5195b5a05b4d9b75b0dd17ed3a1814a65dbd871b0f1c2544eb751a1d359dc43c79f31566a0d622065bc052e81d1e9c85e7847f092d324c3eb9fa3108a713ad4aba6e3e83a7a09a35d0a064fa3c23234d9c119cd9997750810b374ecafe5cc796aeaec0c1c91aa0998f0997b55290ebe6c559acafe73bd9f849e6767215ae1528c3105a03be6399a025f6318ad34f0f8f547c60ec04f0c493dc36785299f9990e205f4e0b2d30e25ca0528c0d8be59ee24c3d272ac94b3d6d3103b8ef79af93741d43160b409554c665a03fb7961e2ba9edcca4fb11df94429039f9acb8d109f2d27833a336d7cc17a519a02c1379f9b1f5d8a793be6e05771b21f3642829166d4792d885afc102661d1670a0d2ea8a36cbcf34989a5b712835b54fabd66727399519792f9103bec780ee1c6aa054d0723bba412cc1c115f034bae8ef9f4228a2a26bcbddf2011688a8f0572fb5a0e3910d471c59010d2684f59c4d515cfc2594f999c116b635a835f4b894261e39a09b28d1913979f901d648df4ca1a2eb767ed921216d6573b26e3320b572e3cda0a0856f1ce14ae5a5f89ddc1363e93f76d3d4ce45b80ee952eaab0a9b656e26b4f080").unwrap(),
            hex::decode("f891808080a0c43fdb165970af44d33ae1ffdd6611b6f428467aa520616c8ab07f8fd70daacd8080808080808080a0808abfb226d55037e6cbcd8d1e2485fa9750162f2b5dc2659e96c984f31df385a0eddf4a0563672f9fb28b577e9503dde13373881695e264e6cae2cd9548b7f6d080a0d1e8257f113c0079a1420ccbd09f10736d878f1fd8c36f23be8854fcf919eaf280").unwrap(),
            hex::decode("e48200aba0f35b68d9f156ea05fd7143c5bdfef9a1ab1cadc6fa2ed36bf2da0b1f76e225af").unwrap(),
            hex::decode("f85180808080808080808080a0706a6615965e183cf3d3e2428b4dad98ecad60c00c00404344220c5407addd9680808080a06d1e9d50927b21b5d854352c9abedbaafd48f720a3aaba3d8be1d31fa21177f780").unwrap(),
            hex::decode("e79d205845a3c1336f12d5c4387c125faf1514a1362932186bf343eb9eed3d8887883a11f9a9d59c").unwrap(),
        ];

        assert_ok!(GovModule::verify_proof(Origin::signed(1), block_number, proof, key, value));

        // Check that the correct event is emitted
		let expected_event = mock::Event::pallet_gov(RawEvent::VerifyProof(true));
		assert_eq!(System::events()[1].event, expected_event,);

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