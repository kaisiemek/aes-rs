#[cfg(test)]
mod test {
    use crate::aes::{
        key::Key,
        modes::{cbc, ecb},
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
        let ciphertext = ecb::encrypt(plaintext.as_slice(), key.clone());
        let cipher_without_padding = ciphertext[..ciphertext.len() - 16].to_vec();

        assert_eq!(cipher_without_padding, expected);
        let decrypted = ecb::decrypt(ciphertext.as_slice(), key).unwrap();
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
        let ciphertext = cbc::encrypt(plaintext.as_slice(), key.clone(), &iv);
        let cipher_without_padding = ciphertext[..ciphertext.len() - 16].to_vec();

        assert_eq!(cipher_without_padding, expected);
        let decrypted = cbc::decrypt(ciphertext.as_slice(), key, &iv).unwrap();
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

    fn get_nist_test_iv() -> [u8; 16] {
        string_to_vec(concat!("00010203 04050607 08090A0B 0C0D0E0F").to_string())
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
