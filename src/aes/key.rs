use super::{
    constants::{
        ENCRYPTION_ROUNDS_AES128, KEY_ROUND_CONSTANTS, KEY_SIZE_AES128, ROUND_KEY_SIZE, S_BOXES,
    },
    helpers::fmt_16_byte_array,
};
use std::{fmt::Display, ops::Index};

#[derive(Default)]
pub struct Key128 {
    round_keys: Vec<RoundKey>,
}

#[derive(Debug, Default)]
pub struct RoundKey {
    data: [u8; ROUND_KEY_SIZE],
}

impl Key128 {
    pub fn new(data: [u8; KEY_SIZE_AES128]) -> Self {
        Self {
            // the first round key is just the initial key unprocessed
            round_keys: vec![data.into()],
        }
    }

    pub fn expand_key(&mut self) {
        for round in 1..=ENCRYPTION_ROUNDS_AES128 {
            self.generate_round_key(round);
        }
    }

    pub fn get_round_key(&self, round: usize) -> Option<&RoundKey> {
        self.round_keys.get(round)
    }

    pub fn iter(self) -> std::vec::IntoIter<RoundKey> {
        self.round_keys.into_iter()
    }

    fn generate_round_key(&mut self, round: usize) {
        let last_key = self.round_keys.last().expect(
            "round keys were unexpectedly empty, generate_round_key must only be called after the initial key has been added to the vector."
        );

        let mut key_data: [u32; 4] = [0; 4];
        key_data[0] = last_key.get_word(0) ^ last_key.get_rot_sub_rcon_word(3, round);

        for word_index in 1..=3 {
            key_data[word_index] = key_data[word_index - 1] ^ last_key.get_word(word_index);
        }

        self.round_keys.push(key_data.into());
    }
}

impl Display for Key128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for key in self.round_keys.iter() {
            writeln!(f, "{}", key)?;
        }

        Ok(())
    }
}

impl Index<usize> for Key128 {
    type Output = RoundKey;

    fn index(&self, index: usize) -> &Self::Output {
        self.get_round_key(index).unwrap()
    }
}

impl From<[u8; KEY_SIZE_AES128]> for Key128 {
    fn from(value: [u8; KEY_SIZE_AES128]) -> Self {
        Self::new(value)
    }
}

impl RoundKey {
    pub fn get_data(&self) -> &[u8; ROUND_KEY_SIZE] {
        &self.data
    }

    fn get_word(&self, word_index: usize) -> u32 {
        let data_index = word_index * 4;
        u32::from_be_bytes(self.data[data_index..data_index + 4].try_into().unwrap())
    }

    // function from the AES key expansion spec, see
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    // section 5.2 Key Expansion
    fn get_rot_sub_rcon_word(&self, word_index: usize, round: usize) -> u32 {
        let mut word = self.get_word(word_index).to_be_bytes().to_vec();

        // Rcon[i]
        let rcon = KEY_ROUND_CONSTANTS[round - 1];
        // RotWord()
        word.rotate_left(1);
        // SubWord()
        word.iter_mut().for_each(|b| {
            *b = S_BOXES[*b as usize];
        });
        word[0] ^= rcon;

        u32::from_be_bytes(word.try_into().unwrap())
    }
}

impl Display for RoundKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_16_byte_array(&self.data, f)
    }
}

impl From<[u32; 4]> for RoundKey {
    fn from(value: [u32; 4]) -> Self {
        let data = value
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        Self { data }
    }
}

impl From<[u8; 16]> for RoundKey {
    fn from(value: [u8; 16]) -> Self {
        Self { data: value }
    }
}
