use super::{roundkey::RoundKey, size::KeySize, word::Word};
use crate::aes::constants::WORD_SIZE;

pub fn expand_key(key_data: &[u8], key_size: KeySize) -> Result<Vec<RoundKey>, String> {
    if key_data.len() != key_size.byte_size() {
        return Err(format!(
            "invalid key size: expected {} bytes, got {}",
            key_size.byte_size(),
            key_data.len()
        ));
    }

    let expanded_word_size = key_size.expanded_word_size();

    let mut expanded_data: Vec<Word> = Vec::with_capacity(expanded_word_size);
    // the first round key is the key itself
    for word in key_data.chunks(WORD_SIZE) {
        expanded_data.push(word.try_into()?);
    }

    while expanded_data.len() < expanded_word_size {
        expanded_data.push(generate_next_word(
            &expanded_data,
            key_size.expansion_round_word_width(),
        )?);
    }

    Ok(make_round_keys(expanded_data))
}

fn generate_next_word(round_data: &Vec<Word>, round_len: usize) -> Result<Word, String> {
    let index = round_data.len();
    let round = round_data.len() / round_len;
    let round_index = index % round_len;

    if round < 1 {
        return Err("can't generate the next word before the initial key data has been copied to the expanded data vector".to_string());
    }

    // the word for index i i always calculated from i-1 and i-Nr 
    let previous_round_word = round_data[index - round_len];
    let mut previous_word = round_data[index - 1];

    if round_index == 0 {
        previous_word = previous_word.rot_word().sub_word().apply_rcon(round);
    }

    Ok(previous_round_word ^ previous_word)
}

fn make_round_keys(round_data: Vec<Word>) -> Vec<RoundKey> {
    let mut round_keys = Vec::new();
    assert!(
        round_data.len() % 4 == 0,
        "round key data must be a multiple of 4 words, got {}",
        round_data.len()
    );

    round_data.chunks(4).for_each(|chunk| {
        let key_data: [Word; 4] = chunk.try_into().unwrap();
        round_keys.push(key_data.into());
    });

    round_keys
}
