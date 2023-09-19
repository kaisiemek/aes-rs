mod expansion;
pub mod size;
mod tests;

use super::{
    constants::{KEY_SIZE_AES128, KEY_SIZE_AES192, KEY_SIZE_AES256},
    datastructures::block::Block,
    key::{expansion::expand_key, size::KeySize},
};
use std::{fmt::Display, ops::Index};

#[derive(Clone, Default)]
pub struct Key {
    pub key_size: KeySize,
    round_keys: Vec<Block>,
}

impl Key {
    pub fn get_round_key(&self, round: usize) -> Option<&Block> {
        self.round_keys.get(round)
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
    type Output = Block;

    fn index(&self, index: usize) -> &Self::Output {
        self.get_round_key(index).unwrap()
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let key_size = match value.len() {
            KEY_SIZE_AES128 => KeySize::AES128,
            KEY_SIZE_AES192 => KeySize::AES192,
            KEY_SIZE_AES256 => KeySize::AES256,
            _ => return Err(format!("Invalid key size: {}", value.len())),
        };

        Ok(Key {
            key_size,
            round_keys: expand_key(value, key_size)?,
        })
    }
}

impl From<[u8; KEY_SIZE_AES128]> for Key {
    fn from(value: [u8; KEY_SIZE_AES128]) -> Self {
        Self {
            key_size: KeySize::AES128,
            round_keys: expand_key(&value, KeySize::AES128).unwrap(),
        }
    }
}

impl From<[u8; KEY_SIZE_AES192]> for Key {
    fn from(value: [u8; KEY_SIZE_AES192]) -> Self {
        Self {
            key_size: KeySize::AES192,
            round_keys: expand_key(&value, KeySize::AES192).unwrap(),
        }
    }
}

impl From<[u8; KEY_SIZE_AES256]> for Key {
    fn from(value: [u8; KEY_SIZE_AES256]) -> Self {
        Self {
            key_size: KeySize::AES256,
            round_keys: expand_key(&value, KeySize::AES256).unwrap(),
        }
    }
}
