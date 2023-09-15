#[cfg(test)]
mod test {
    use crate::aes::{constants::BLOCK_SIZE, encrypt, key::Key128};

    #[test]
    fn test_key_expansion_128() {
        struct TestCase {
            input_data: [u8; BLOCK_SIZE],
            expected_round_keys: Vec<String>,
        }

        let test_cases = vec![
            TestCase {
                input_data: [
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
                input_data: [
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
            TestCase {
                input_data: [
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
        ];

        for test_case in test_cases {
            let key = Key128::new(test_case.input_data);

            for i in 0..11 {
                let round_key = &key[i];
                assert_eq!(round_key.to_string(), test_case.expected_round_keys[i]);
            }
        }
    }

    #[test]
    fn test_encryption() {
        // NIST test plaintext
        let plaintext: Vec<u8> = vec![
            vec![
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ],
            vec![
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                0x8e, 0x51,
            ],
            vec![
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a,
                0x52, 0xef,
            ],
            vec![
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c,
                0x37, 0x10,
            ],
        ]
        .into_iter()
        .flatten()
        .collect();

        // NIST test key
        let key = Key128::from([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]);

        // NIST test ciphertext + padding
        let expected_ciphertext: Vec<u8> = vec![
            vec![
                0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
                0xef, 0x97,
            ],
            vec![
                0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd,
                0xba, 0xaf,
            ],
            vec![
                0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03,
                0x06, 0x88,
            ],
            vec![
                0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72,
                0x5d, 0xd4,
            ],
            // padding
            vec![
                0xf6, 0xc7, 0x1e, 0xed, 0xc3, 0xd9, 0x9b, 0xb1, 0x83, 0xcb, 0x5b, 0x8d, 0x15, 0x68,
                0xe6, 0x06,
            ],
        ]
        .into_iter()
        .flatten()
        .collect();

        let ciphertext = encrypt(plaintext.as_slice(), key);
        assert_eq!(ciphertext, expected_ciphertext);
    }
}
