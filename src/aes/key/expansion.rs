use super::{roundkey::RoundKey, word::Word};
use crate::aes::constants::{ENCRYPTION_ROUNDS_AES128, KEY_SIZE_AES128};

pub fn expand_key_128(key_data: [u8; KEY_SIZE_AES128]) -> Vec<RoundKey> {
    let mut round_key_data: Vec<[Word; 4]> = vec![];

    // the first round key is the key itself
    let mut current_round: [Word; 4] = Default::default();
    for (i, chunk) in key_data.chunks(4).enumerate() {
        current_round[i] = chunk.try_into().unwrap();
    }
    round_key_data.push(current_round);

    while round_key_data.len() < ENCRYPTION_ROUNDS_AES128 + 1 {
        round_key_data.push(generate_round_keys_128(&round_key_data));
    }

    round_key_data.into_iter().map(|key| key.into()).collect()
}

fn generate_round_keys_128(round_data: &Vec<[Word; 4]>) -> [Word; 4] {
    let previous_round = round_data.last().expect(
            "round keys were unexpectedly empty, generate_round_key must only be called after the initial key has been added to the vector."
        );
    let mut current_round: [Word; 4] = Default::default();

    current_round[0] = previous_round[0]
        ^ previous_round[3]
            .rot_word()
            .sub_word()
            .apply_rcon(round_data.len());

    for word_index in 1..4 {
        current_round[word_index] = current_round[word_index - 1] ^ previous_round[word_index];
    }

    current_round
}
