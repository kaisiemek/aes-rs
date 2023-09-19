use crate::aes::{
    constants::{ROUND_KEY_SIZE, WORD_SIZE},
    datastructures::{block::Block, word::Word},
    key::size::KeySize,
};

pub fn expand_key(key_data: &[u8], key_size: KeySize) -> Result<Vec<Block>, String> {
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
        expanded_data.push(generate_next_word(&expanded_data, key_size)?);
    }

    make_round_keys(expanded_data)
}

fn generate_next_word(round_data: &Vec<Word>, key_size: KeySize) -> Result<Word, String> {
    let index = round_data.len();
    let round_words = key_size.expansion_round_word_width();
    let round = round_data.len() / round_words;
    let round_index = index % round_words;

    if round < 1 {
        return Err("can't generate the next word before the initial key data has been copied to the expanded data vector".to_string());
    }

    // always calculcate the next word from the word with the same index in the previous round
    // and the previously generated word
    let previous_round_word = round_data[(round - 1) * round_words + round_index];

    // for the first word of each expansion round the previous word is always rotated,
    // the bytes are substituted and the round constant is applied.
    // additionally, if a 256-bit key is used, then for the fifth word of each expansion round
    // the previous words' bytes are substituted.
    let previous_word = if round_index == 0 {
        round_data[index - 1]
            .rot_word()
            .sub_word()
            .apply_rcon(round)
    } else if round_index == 4 && key_size == KeySize::AES256 {
        round_data[index - 1].sub_word()
    } else {
        round_data[index - 1]
    };

    Ok(previous_round_word ^ previous_word)
}

fn make_round_keys(round_data: Vec<Word>) -> Result<Vec<Block>, String> {
    let mut round_keys = Vec::new();

    if round_data.len() % (ROUND_KEY_SIZE / WORD_SIZE) != 0 {
        return Err(format!(
            "round key data must be a multiple of 4 words, got {} words",
            round_data.len()
        ));
    }

    round_data.chunks(4).for_each(|chunk| {
        let key_data: [Word; 4] = chunk.try_into().unwrap();
        round_keys.push(key_data.into());
    });

    Ok(round_keys)
}
