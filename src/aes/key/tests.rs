#[cfg(test)]
mod test {
    use crate::aes::key::Key;

    #[test]
    fn test_key_expansion() {
        struct TestCase {
            input_data: Vec<u8>,
            expected_round_keys: Vec<String>,
        }

        let test_cases = vec![
            TestCase {
                input_data: vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
                    0x13, 0x14, 0x15,
                ],
                expected_round_keys: vec![
                    "00010203 04050607 08091011 12131415".to_string(),
                    "7cfb5bca 78fe5dcd 70f74ddc 62e459c9".to_string(),
                    "17308660 6fcedbad 1f399671 7dddcfb8".to_string(),
                    "d2baea9f bd743132 a24da743 df9068fb".to_string(),
                    "baffe501 078bd433 a5c67370 7a561b8b".to_string(),
                    "1b50d8db 1cdb0ce8 b91d7f98 c34b6413".to_string(),
                    "8813a5f5 94c8a91d 2dd5d685 ee9eb296".to_string(),
                    "c32435dd 57ec9cc0 7a394a45 94a7f8d3".to_string(),
                    "1f6553ff 4889cf3f 32b0857a a6177da9".to_string(),
                    "f49a80db bc134fe4 8ea3ca9e 28b4b737".to_string(),
                    "4f331aef f320550b 7d839f95 553728a2".to_string(),
                ],
            },
            TestCase {
                input_data: vec![
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                expected_round_keys: vec![
                    "00000000 00000000 00000000 00000000".to_string(),
                    "62636363 62636363 62636363 62636363".to_string(),
                    "9b9898c9 f9fbfbaa 9b9898c9 f9fbfbaa".to_string(),
                    "90973450 696ccffa f2f45733 0b0fac99".to_string(),
                    "ee06da7b 876a1581 759e42b2 7e91ee2b".to_string(),
                    "7f2e2b88 f8443e09 8dda7cbb f34b9290".to_string(),
                    "ec614b85 1425758c 99ff0937 6ab49ba7".to_string(),
                    "21751787 3550620b acaf6b3c c61bf09b".to_string(),
                    "0ef90333 3ba96138 97060a04 511dfa9f".to_string(),
                    "b1d4d8e2 8a7db9da 1d7bb3de 4c664941".to_string(),
                    "b4ef5bcb 3e92e211 23e951cf 6f8f188e".to_string(),
                ],
            },
            // NIST AES spec 128 bit sample key expansion
            TestCase {
                input_data: vec![
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ],
                expected_round_keys: vec![
                    "2b7e1516 28aed2a6 abf71588 09cf4f3c".to_string(),
                    "a0fafe17 88542cb1 23a33939 2a6c7605".to_string(),
                    "f2c295f2 7a96b943 5935807a 7359f67f".to_string(),
                    "3d80477d 4716fe3e 1e237e44 6d7a883b".to_string(),
                    "ef44a541 a8525b7f b671253b db0bad00".to_string(),
                    "d4d1c6f8 7c839d87 caf2b8bc 11f915bc".to_string(),
                    "6d88a37a 110b3efd dbf98641 ca0093fd".to_string(),
                    "4e54f70e 5f5fc9f3 84a64fb2 4ea6dc4f".to_string(),
                    "ead27321 b58dbad2 312bf560 7f8d292f".to_string(),
                    "ac7766f3 19fadc21 28d12941 575c006e".to_string(),
                    "d014f9a8 c9ee2589 e13f0cc8 b6630ca6".to_string(),
                ],
            },
            // NIST AES spec 192 bit sample key expansion
            TestCase {
                input_data: vec![
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80,
                    0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
                ],
                expected_round_keys: vec![
                    "8e73b0f7 da0e6452 c810f32b 809079e5".to_string(),
                    "62f8ead2 522c6b7b fe0c91f7 2402f5a5".to_string(),
                    "ec12068e 6c827f6b 0e7a95b9 5c56fec2".to_string(),
                    "4db7b4bd 69b54118 85a74796 e92538fd".to_string(),
                    "e75fad44 bb095386 485af057 21efb14f".to_string(),
                    "a448f6d9 4d6dce24 aa326360 113b30e6".to_string(),
                    "a25e7ed5 83b1cf9a 27f93943 6a94f767".to_string(),
                    "c0a69407 d19da4e1 ec1786eb 6fa64971".to_string(),
                    "485f7032 22cb8755 e26d1352 33f0b7b3".to_string(),
                    "40beeb28 2f18a259 6747d26b 458c553e".to_string(),
                    "a7e1466c 9411f1df 821f750a ad07d753".to_string(),
                    "6747d26b ca400538 458c553e 8fcc5006".to_string(),
                    "a7e1466c 282d166a 9411f1df bc3ce7b5".to_string(),
                    "821f750a e98ba06f ad07d753 448c773c".to_string(),
                    "ca400538 8ecc7204 8fcc5006 01002202".to_string(),
                ],
            },
            // NIST AES spec 256 bit sample key expansion
            TestCase {
                input_data: vec![
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
                    0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
                    0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
                ],
                expected_round_keys: vec![
                    "603deb10 15ca71be 2b73aef0 857d7781".to_string(),
                    "1f352c07 3b6108d7 2d9810a3 0914dff4".to_string(),
                    "9ba35411 8e6925af a51a8b5f 2067fcde".to_string(),
                    "a8b09c1a 93d194cd be49846e b75d5b9a".to_string(),
                    "d59aecb8 5bf3c917 fee94248 de8ebe96".to_string(),
                    "b5a9328a 2678a647 98312229 2f6c79b3".to_string(),
                    "812c81ad dadf48ba 24360af2 fab8b464".to_string(),
                    "98c5bfc9 bebd198e 268c3ba7 09e04214".to_string(),
                    "68007bac b2df3316 96e939e4 6c518d80".to_string(),
                    "c814e204 76a9fb8a 5025c02d 59c58239".to_string(),
                    "de136967 6ccc5a71 fa256395 9674ee15".to_string(),
                    "5886ca5d 2e2f31d7 7e0af1fa 27cf73c3".to_string(),
                    "749c47ab 18501dda e2757e4f 7401905a".to_string(),
                    "cafaaae3 e4d59b34 9adf6ace bd10190d".to_string(),
                    "fe4890d1 e6188d0b 046df344 706c631e".to_string(),
                ],
            },
        ];

        for test_case in test_cases {
            let key: Key = test_case.input_data.as_slice().try_into().unwrap();

            for i in 0..11 {
                let round_key = &key[i];
                assert_eq!(round_key.to_string(), test_case.expected_round_keys[i]);
            }
        }
    }
}
