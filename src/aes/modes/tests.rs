#[cfg(test)]
mod test {
    use crate::aes::{
        config::AESConfig,
        datastructures::block::Block,
        key::Key,
        modes::{cbc, cfb, ctr, ecb, ofb, CFBSegmentSize, OperationMode},
    };

    #[test]
    fn test_aes128_ecb() {
        let key = get_nist_test_key_128();
        let expected_ciphertext = string_to_vec(
            concat!(
                "3AD77BB4 0D7A3660 A89ECAF3 2466EF97",
                "F5D3D585 03B9699D E785895A 96FDBAAF",
                "43B1CD7F 598ECE23 881B00E3 ED030688",
                "7B0C785E 27E8AD3F 82232071 04725DD4",
            )
            .to_string(),
        );

        run_ecb(expected_ciphertext, key);
    }

    #[test]
    fn test_aes192_ecb() {
        let key = get_nist_test_key_192();
        let expected_ciphertext = string_to_vec(
            concat!(
                "BD334F1D 6E45F25F F712A214 571FA5CC",
                "97410484 6D0AD3AD 7734ECB3 ECEE4EEF",
                "EF7AFD22 70E2E60A DCE0BA2F ACE6444E",
                "9A4B41BA 738D6C72 FB166916 03C18E0E",
            )
            .to_string(),
        );

        run_ecb(expected_ciphertext, key);
    }

    #[test]
    fn test_aes256_ecb() {
        let key = get_nist_test_key_256();
        let expected_ciphertext = string_to_vec(
            concat!(
                "F3EED1BD B5D2A03C 064B5A7E 3DB181F8",
                "591CCB10 D410ED26 DC5BA74A 31362870",
                "B6ED21B9 9CA6F4F9 F153E7B1 BEAFED1D",
                "23304B7A 39F9F3FF 067D8D8F 9E24ECC7",
            )
            .to_string(),
        );

        run_ecb(expected_ciphertext, key);
    }

    fn run_ecb(expected: Vec<u8>, key: Key) {
        let plaintext = get_nist_test_plaintext();
        let config = AESConfig::new(key, OperationMode::ECB);

        let ciphertext = ecb::encrypt(plaintext.as_slice(), &config).unwrap();

        let mut ciphertext_no_padding = ciphertext.clone();
        ciphertext_no_padding.truncate(ciphertext_no_padding.len() - 16);
        assert_eq!(ciphertext_no_padding, expected);

        let decrypted = ecb::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_cbc() {
        let key = get_nist_test_key_128();
        let expected_ciphertext = string_to_vec(
            concat!(
                "7649ABAC 8119B246 CEE98E9B 12E9197D",
                "5086CB9B 507219EE 95DB113A 917678B2",
                "73BED6B8 E3C1743B 7116E69E 22229516",
                "3FF1CAA1 681FAC09 120ECA30 7586E1A7",
            )
            .to_string(),
        );

        run_cbc(expected_ciphertext, key);
    }

    #[test]
    fn test_aes192_cbc() {
        let key = get_nist_test_key_192();
        let expected_ciphertext = string_to_vec(
            concat!(
                "4F021DB2 43BC633D 7178183A 9FA071E8",
                "B4D9ADA9 AD7DEDF4 E5E73876 3F69145A",
                "571B2420 12FB7AE0 7FA9BAAC 3DF102E0",
                "08B0E279 88598881 D920A9E6 4F5615CD",
            )
            .to_string(),
        );

        run_cbc(expected_ciphertext, key);
    }

    #[test]
    fn test_aes256_cbc() {
        let key = get_nist_test_key_256();
        let expected_ciphertext = string_to_vec(
            concat!(
                "F58C4C04 D6E5F1BA 779EABFB 5F7BFBD6",
                "9CFC4E96 7EDB808D 679F777B C6702C7D",
                "39F23369 A9D9BACF A530E263 04231461",
                "B2EB05E2 C39BE9FC DA6C1907 8C6A9D1B",
            )
            .to_string(),
        );

        run_cbc(expected_ciphertext, key);
    }

    fn run_cbc(expected: Vec<u8>, key: Key) {
        let plaintext = get_nist_test_plaintext();
        let iv = get_nist_test_iv();
        let config = AESConfig::new(key, OperationMode::CBC { iv });

        let ciphertext = cbc::encrypt(plaintext.as_slice(), &config).unwrap();

        let mut ciphertext_no_padding = ciphertext.clone();
        ciphertext_no_padding.truncate(ciphertext_no_padding.len() - 16);
        assert_eq!(ciphertext_no_padding, expected);

        let decrypted = cbc::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_ofb() {
        let key = get_nist_test_key_128();
        let expected_ciphertext = string_to_vec(
            concat!(
                "3B3FD92E B72DAD20 333449F8 E83CFB4A",
                "7789508D 16918F03 F53C52DA C54ED825",
                "9740051E 9C5FECF6 4344F7A8 2260EDCC",
                "304C6528 F659C778 66A510D9 C1D6AE5E",
            )
            .to_string(),
        );

        run_ofb(expected_ciphertext.clone(), key.clone());
        run_partial_ofb(expected_ciphertext, key);
    }

    #[test]
    fn test_aes192_ofb() {
        let key = get_nist_test_key_192();
        let expected_ciphertext = string_to_vec(
            concat!(
                "CDC80D6F DDF18CAB 34C25909 C99A4174",
                "FCC28B8D 4C63837C 09E81700 C1100401",
                "8D9A9AEA C0F6596F 559C6D4D AF59A5F2",
                "6D9F2008 57CA6C3E 9CAC524B D9ACC92A",
            )
            .to_string(),
        );

        run_ofb(expected_ciphertext.clone(), key.clone());
        run_partial_ofb(expected_ciphertext, key);
    }

    #[test]
    fn test_aes256_ofb() {
        let key = get_nist_test_key_256();
        let expected_ciphertext = string_to_vec(
            concat!(
                "DC7E84BF DA79164B 7ECD8486 985D3860",
                "4FEBDC67 40D20B3A C88F6AD8 2A4FB08D",
                "71AB47A0 86E86EED F39D1C5B BA97C408",
                "0126141D 67F37BE8 538F5A8B E740E484",
            )
            .to_string(),
        );

        run_ofb(expected_ciphertext.clone(), key.clone());
        run_partial_ofb(expected_ciphertext, key);
    }

    fn run_ofb(expected: Vec<u8>, key: Key) {
        let plaintext = get_nist_test_plaintext();
        let iv = get_nist_test_iv();
        let config = AESConfig::new(key, OperationMode::OFB { iv });

        let ciphertext = ofb::encrypt(plaintext.as_slice(), &config).unwrap();
        assert_eq!(ciphertext, expected);

        let decrypted = ofb::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    fn run_partial_ofb(mut expected: Vec<u8>, key: Key) {
        let mut plaintext = get_nist_test_plaintext();
        plaintext.pop();
        plaintext.pop();
        expected.pop();
        expected.pop();

        let iv = get_nist_test_iv();

        let config = AESConfig::new(key, OperationMode::OFB { iv });

        let ciphertext = ofb::encrypt(plaintext.as_slice(), &config).unwrap();
        assert_eq!(ciphertext, expected);

        let decrypted = ofb::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_cfb_128() {
        let key = get_nist_test_key_128();
        let expected_ciphertext = string_to_vec(
            concat!(
                "3B3FD92E B72DAD20 333449F8 E83CFB4A",
                "C8A64537 A0B3A93F CDE3CDAD 9F1CE58B",
                "26751F67 A3CBB140 B1808CF1 87A4F4DF",
                "C04B0535 7C5D1C0E EAC4C66F 9FF7F2E6",
            )
            .to_string(),
        );

        run_cfb_128(expected_ciphertext.clone(), key.clone());
        run_partial_cfb_128(expected_ciphertext, key);
    }

    #[test]
    fn test_aes192_cfb_128() {
        let key = get_nist_test_key_192();
        let expected_ciphertext = string_to_vec(
            concat!(
                "CDC80D6F DDF18CAB 34C25909 C99A4174",
                "67CE7F7F 81173621 961A2B70 171D3D7A",
                "2E1E8A1D D59B88B1 C8E60FED 1EFAC4C9",
                "C05F9F9C A9834FA0 42AE8FBA 584B09FF",
            )
            .to_string(),
        );

        run_cfb_128(expected_ciphertext.clone(), key.clone());
        run_partial_cfb_128(expected_ciphertext, key);
    }

    #[test]
    fn test_aes256_cfb_128() {
        let key = get_nist_test_key_256();
        let expected_ciphertext = string_to_vec(
            concat!(
                "DC7E84BF DA79164B 7ECD8486 985D3860",
                "39FFED14 3B28B1C8 32113C63 31E5407B",
                "DF101324 15E54B92 A13ED0A8 267AE2F9",
                "75A38574 1AB9CEF8 2031623D 55B1E471",
            )
            .to_string(),
        );

        run_cfb_128(expected_ciphertext.clone(), key.clone());
        run_partial_cfb_128(expected_ciphertext, key);
    }

    fn run_cfb_128(expected: Vec<u8>, key: Key) {
        let plaintext = get_nist_test_plaintext();
        let iv = get_nist_test_iv();
        let config = AESConfig::new(
            key,
            OperationMode::CFB {
                iv,
                seg_size: CFBSegmentSize::Bit128,
            },
        );

        let ciphertext = cfb::encrypt(plaintext.as_slice(), &config).unwrap();
        assert_eq!(ciphertext, expected);

        let decrypted = cfb::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    fn run_partial_cfb_128(mut expected: Vec<u8>, key: Key) {
        let mut plaintext = get_nist_test_plaintext();
        plaintext.pop();
        plaintext.pop();
        expected.pop();
        expected.pop();

        let iv = get_nist_test_iv();
        let config = AESConfig::new(
            key,
            OperationMode::CFB {
                iv,
                seg_size: CFBSegmentSize::Bit128,
            },
        );

        let ciphertext = cfb::encrypt(plaintext.as_slice(), &config).unwrap();
        assert_eq!(ciphertext, expected);

        let decrypted = cfb::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_cfb_8() {
        let key = get_nist_test_key_128();
        let expected_ciphertext =
            string_to_vec(concat!("3B79424C 9C0DD436 BACE9E0E D4586A4F").to_string());

        run_cfb_8(expected_ciphertext.clone(), key.clone());
        run_partial_cfb_8(expected_ciphertext, key);
    }

    #[test]
    fn test_aes192_cfb_8() {
        let key = get_nist_test_key_192();
        let expected_ciphertext =
            string_to_vec(concat!("CDA2521E F0A905CA 44CD057C BF0D47A0").to_string());

        run_cfb_8(expected_ciphertext.clone(), key.clone());
        run_partial_cfb_8(expected_ciphertext, key);
    }

    #[test]
    fn test_aes256_cfb_8() {
        let key = get_nist_test_key_256();
        let expected_ciphertext =
            string_to_vec(concat!("DC1F1A85 20A64DB5 5FCC8AC5 54844E88").to_string());

        run_cfb_8(expected_ciphertext.clone(), key.clone());
        run_partial_cfb_8(expected_ciphertext, key);
    }

    fn run_cfb_8(expected: Vec<u8>, key: Key) {
        let mut plaintext = get_nist_test_plaintext();
        plaintext.truncate(expected.len());

        let iv = get_nist_test_iv();
        let config = AESConfig::new(
            key,
            OperationMode::CFB {
                iv,
                seg_size: CFBSegmentSize::Bit8,
            },
        );

        let ciphertext = cfb::encrypt(plaintext.as_slice(), &config).unwrap();
        assert_eq!(ciphertext, expected);

        let decrypted = cfb::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    fn run_partial_cfb_8(mut expected: Vec<u8>, key: Key) {
        let mut plaintext = get_nist_test_plaintext();
        plaintext.truncate(expected.len() - 1);
        expected.pop();

        let iv = get_nist_test_iv();
        let config = AESConfig::new(
            key,
            OperationMode::CFB {
                iv,
                seg_size: CFBSegmentSize::Bit8,
            },
        );

        let ciphertext = cfb::encrypt(plaintext.as_slice(), &config).unwrap();
        assert_eq!(ciphertext, expected);

        let decrypted = cfb::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_ctr() {
        let key = get_nist_test_key_128();
        let expected_ciphertext = string_to_vec(
            concat!(
                "874D6191 B620E326 1BEF6864 990DB6CE",
                "9806F66B 7970FDFF 8617187B B9FFFDFF",
                "5AE4DF3E DBD5D35E 5B4F0902 0DB03EAB",
                "1E031DDA 2FBE03D1 792170A0 F3009CEE",
            )
            .to_string(),
        );

        run_ctr(expected_ciphertext.clone(), key.clone());
        run_partial_ctr(expected_ciphertext, key);
    }

    #[test]
    fn test_aes192_ctr() {
        let key = get_nist_test_key_192();
        let expected_ciphertext = string_to_vec(
            concat!(
                "1ABC9324 17521CA2 4F2B0459 FE7E6E0B",
                "090339EC 0AA6FAEF D5CCC2C6 F4CE8E94",
                "1E36B26B D1EBC670 D1BD1D66 5620ABF7",
                "4F78A7F6 D2980958 5A97DAEC 58C6B050",
            )
            .to_string(),
        );

        run_ctr(expected_ciphertext.clone(), key.clone());
        run_partial_ctr(expected_ciphertext, key);
    }

    #[test]
    fn test_aes256_ctr() {
        let key = get_nist_test_key_256();
        let expected_ciphertext = string_to_vec(
            concat!(
                "601EC313 775789A5 B7A7F504 BBF3D228",
                "F443E3CA 4D62B59A CA84E990 CACAF5C5",
                "2B0930DA A23DE94C E87017BA 2D84988D",
                "DFC9C58D B67AADA6 13C2DD08 457941A6",
            )
            .to_string(),
        );

        run_ctr(expected_ciphertext.clone(), key.clone());
        run_partial_ctr(expected_ciphertext, key);
    }

    fn run_ctr(expected: Vec<u8>, key: Key) {
        let plaintext = get_nist_test_plaintext();
        let iv = get_nist_initial_counter();
        let config = AESConfig::new(key, OperationMode::CTR { iv });

        let ciphertext = ctr::encrypt(plaintext.as_slice(), &config).unwrap();
        assert_eq!(ciphertext, expected);

        let decrypted = ctr::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    fn run_partial_ctr(mut expected: Vec<u8>, key: Key) {
        let mut plaintext = get_nist_test_plaintext();
        plaintext.pop();
        plaintext.pop();
        expected.pop();
        expected.pop();

        let iv = get_nist_initial_counter();
        let config = AESConfig::new(key, OperationMode::CTR { iv });

        let ciphertext = ctr::encrypt(plaintext.as_slice(), &config).unwrap();
        assert_eq!(ciphertext, expected);

        let decrypted = ctr::decrypt(ciphertext.as_slice(), &config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    fn get_nist_test_plaintext() -> Vec<u8> {
        string_to_vec(
            concat!(
                "6BC1BEE2 2E409F96 E93D7E11 7393172A",
                "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51",
                "30C81C46 A35CE411 E5FBC119 1A0A52EF",
                "F69F2445 DF4F9B17 AD2B417B E66C3710"
            )
            .to_string(),
        )
    }

    fn get_nist_test_iv() -> Block {
        string_to_vec(concat!("00010203 04050607 08090A0B 0C0D0E0F").to_string())
            .try_into()
            .unwrap()
    }

    fn get_nist_initial_counter() -> Block {
        string_to_vec("F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF".to_string())
            .try_into()
            .unwrap()
    }

    fn get_nist_test_key_128() -> Key {
        let key_data = string_to_vec(concat!("2B7E1516 28AED2A6 ABF71588 09CF4F3C").to_string());
        key_data.as_slice().try_into().unwrap()
    }

    fn get_nist_test_key_192() -> Key {
        let key_data = string_to_vec(
            concat!("8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B").to_string(),
        );
        key_data.as_slice().try_into().unwrap()
    }

    fn get_nist_test_key_256() -> Key {
        let key_data = string_to_vec(
            concat!(
                "603DEB10 15CA71BE 2B73AEF0 857D7781",
                "1F352C07 3B6108D7 2D9810A3 0914DFF4"
            )
            .to_string(),
        );
        key_data.as_slice().try_into().unwrap()
    }

    fn string_to_vec(mut str: String) -> Vec<u8> {
        str = str.replace(' ', "");
        str = str.replace('\n', "");
        (0..str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&str[i..i + 2], 16).unwrap())
            .collect()
    }
}
