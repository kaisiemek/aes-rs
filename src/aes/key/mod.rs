mod expansion;
pub mod roundkey;
mod size;
mod word;

use self::{expansion::expand_key_128, roundkey::RoundKey, size::KeySize};
use super::constants::KEY_SIZE_AES128;
use std::{fmt::Display, ops::Index};

#[derive(Clone, Default)]
pub struct Key {
    key_size: KeySize,
    round_keys: Vec<RoundKey>,
}

impl Key {
    pub fn get_round_key(&self, round: usize) -> Option<&RoundKey> {
        self.round_keys.get(round)
    }

    pub fn iter(self) -> std::vec::IntoIter<RoundKey> {
        self.round_keys.into_iter()
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, key) in self.round_keys.iter().enumerate() {
            writeln!(f, "{:02}: {}", i, key)?;
        }

        Ok(())
    }
}

impl Index<usize> for Key {
    type Output = RoundKey;

    fn index(&self, index: usize) -> &Self::Output {
        self.get_round_key(index).unwrap()
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            KEY_SIZE_AES128 => {
                let key_data: [u8; KEY_SIZE_AES128] = value.try_into().unwrap();
                Ok(key_data.into())
            }
            KEY_SIZE_AES192 => todo!(),
            KEY_SIZE_AES256 => todo!(),
            byte_len => Err(format!("Invalid key size: {}", byte_len)),
        }
    }
}

impl From<[u8; KEY_SIZE_AES128]> for Key {
    fn from(value: [u8; KEY_SIZE_AES128]) -> Self {
        Self {
            key_size: KeySize::AES128,
            round_keys: expand_key_128(value),
        }
    }
}
