#[cfg(test)]
mod test {
    use crate::aes::{block::AESBlock, constants::BLOCK_SIZE, key::Key128};

    #[test]
    fn test_shift_row() {
        struct TestCase {
            input_data: [u8; BLOCK_SIZE],
            expected_output: String,
        }

        let test_cases = vec![
            TestCase {
                input_data: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
                    0x13, 0x14, 0x15,
                ],
                expected_output: "00051015 04091403 08130207 12010611".to_string(),
            },
            TestCase {
                input_data: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                expected_output: "00000000 00000000 00000000 00000000".to_string(),
            },
            TestCase {
                input_data: [
                    0x00, 0x00, 0x01, 0x01, 0x03, 0x03, 0x07, 0x07, 0x0f, 0x0f, 0x1f, 0x1f, 0x3f,
                    0x3f, 0x7f, 0x7f,
                ],
                expected_output: "00031f7f 030f7f01 0f3f0107 3f00071f".to_string(),
            },
            TestCase {
                input_data: [
                    0x12, 0x22, 0xab, 0xc3, 0xde, 0x12, 0x33, 0x98, 0x75, 0xf7, 0xb2, 0x00, 0xe4,
                    0xe7, 0x60, 0x10,
                ],
                expected_output: "1212b210 def760c3 75e7ab98 e4223300".to_string(),
            },
        ];

        for test_case in test_cases {
            let mut block = AESBlock::new(&test_case.input_data);
            block.shift_rows();
            assert_eq!(block.to_string(), test_case.expected_output);
        }
    }

    #[test]
    fn test_mix_col() {
        struct TestCase {
            input_data: [u8; BLOCK_SIZE],
            expected_output: String,
        }

        let test_cases = vec![
            TestCase {
                input_data: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
                    0x13, 0x14, 0x15,
                ],
                expected_output: "02070005 06030401 0a3b1223 101d161b".to_string(),
            },
            TestCase {
                input_data: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                expected_output: "00000000 00000000 00000000 00000000".to_string(),
            },
            TestCase {
                input_data: [
                    0x00, 0x00, 0x01, 0x01, 0x03, 0x03, 0x07, 0x07, 0x0f, 0x0f, 0x1f, 0x1f, 0x3f,
                    0x3f, 0x7f, 0x7f,
                ],
                expected_output: "00020103 030b070f 0f2f1f3f 3fbf7fff".to_string(),
            },
            TestCase {
                input_data: [
                    0x12, 0x22, 0xab, 0xc3, 0xde, 0x12, 0x33, 0x98, 0x75, 0xf7, 0xb2, 0x00, 0xe4,
                    0xe7, 0x60, 0x10,
                ],
                expected_output: "2a732322 3a371973 5a4dfdda 9181f390".to_string(),
            },
        ];

        for test_case in test_cases {
            let mut block = AESBlock::new(&test_case.input_data);
            block.mix_columns();
            assert_eq!(block.to_string(), test_case.expected_output);
        }
    }

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
            let mut key = Key128::new(test_case.input_data);
            key.expand_key();

            for i in 0..11 {
                let round_key = key.get_key(i);
                assert_eq!(round_key.to_string(), test_case.expected_round_keys[i]);
            }
        }
    }
}
