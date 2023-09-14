use std::fmt::Display;

use super::constants::{
    ENCRYPTION_ROUNDS_AES128, KEY_ROUND_CONSTANTS, KEY_SIZE_AES128, KEY_SIZE_EXPANDED_AES128,
    ROUND_KEY_SIZE, S_BOXES,
};

pub struct Key128 {
    data: [u8; KEY_SIZE_AES128],
    expanded_data: [u32; KEY_SIZE_EXPANDED_AES128],
}

pub struct RoundKey {
    data: [u8; ROUND_KEY_SIZE],
}

impl Key128 {
    pub fn new(data: [u8; KEY_SIZE_AES128]) -> Self {
        Self {
            data,
            expanded_data: [0; KEY_SIZE_EXPANDED_AES128],
        }
    }

    pub fn expand_key(&mut self) {
        self.copy_initial_keydata();

        for round in 1..=ENCRYPTION_ROUNDS_AES128 {
            self.generate_round_key(round);
        }
    }

    pub fn get_key(&self, round: usize) -> RoundKey {
        let words: [u32; 4] = self
            .expanded_data
            .iter()
            .cloned()
            .skip(round * 4)
            .take(4)
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        words.into()
    }

    fn generate_round_key(&mut self, round: usize) {
        let first_word = round * 4;
        self.expanded_data[first_word] = self.expanded_data[first_word - 4]
            ^ process_word(self.expanded_data[first_word - 1], round);

        for cur_word in first_word + 1..first_word + 4 {
            self.expanded_data[cur_word] =
                self.expanded_data[cur_word - 1] ^ self.expanded_data[cur_word - 4];
        }
    }

    fn copy_initial_keydata(&mut self) {
        for i in (0..self.data.len()).step_by(4) {
            self.expanded_data[i / 4] = u32::from_be_bytes(self.data[i..i + 4].try_into().unwrap());
        }
    }
}

// function from the AES key expansion spec, see
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
// section 5.2 Key Expansion
fn process_word(word: u32, round: usize) -> u32 {
    let mut bytes = word.to_be_bytes().to_vec();

    // Rcon[i]
    let rcon = KEY_ROUND_CONSTANTS[round - 1];
    // RotWord()
    bytes.rotate_left(1);
    // SubWord()
    bytes.iter_mut().for_each(|b| {
        *b = S_BOXES[*b as usize];
    });
    bytes[0] ^= rcon;

    u32::from_be_bytes(bytes.try_into().unwrap())
}

impl Display for Key128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for round in 0..ENCRYPTION_ROUNDS_AES128 + 1 {
            writeln!(f, "{}", self.get_key(round))?;
        }
        Ok(())
    }
}

impl Display for RoundKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let word_to_str = |word: &[u8]| -> String {
            word.iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<String>>()
                .join("")
        };

        let key_str = self
            .data
            .chunks(4)
            .map(word_to_str)
            .collect::<Vec<String>>()
            .join(" ");

        write!(f, "{}", key_str)
    }
}

impl From<[u32; 4]> for RoundKey {
    fn from(value: [u32; 4]) -> Self {
        let data = value
            .iter()
            .map(|word| word.to_be_bytes())
            .flatten()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        Self { data }
    }
}
