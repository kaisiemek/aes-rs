use super::word::Word;
use crate::aes::{constants::ROUND_KEY_SIZE, helpers::fmt_16_byte_array};
use std::fmt::Display;

#[derive(Clone, Debug, Default)]
pub struct RoundKey {
    data: [u8; ROUND_KEY_SIZE],
}

impl RoundKey {
    pub fn get_data(&self) -> &[u8; ROUND_KEY_SIZE] {
        &self.data
    }
}

impl Display for RoundKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_16_byte_array(&self.data, f)
    }
}

impl From<[Word; 4]> for RoundKey {
    fn from(value: [Word; 4]) -> Self {
        let data = value
            .iter()
            .flat_map(|word| word.data)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        Self { data }
    }
}
