use crate::aes::constants::{
    ENCRYPTION_ROUNDS_AES128, ENCRYPTION_ROUNDS_AES192, ENCRYPTION_ROUNDS_AES256,
    EXPANDED_KEY_SIZE_AES128, EXPANDED_KEY_SIZE_AES192, EXPANDED_KEY_SIZE_AES256, KEY_SIZE_AES128,
    KEY_SIZE_AES192, KEY_SIZE_AES256, ROUND_WORDS_AES128, ROUND_WORDS_AES192, ROUND_WORDS_AES256,
    WORD_SIZE,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeySize {
    AES128,
    AES192,
    AES256,
}

impl KeySize {
    pub fn byte_size(&self) -> usize {
        match self {
            KeySize::AES128 => KEY_SIZE_AES128,
            KeySize::AES192 => KEY_SIZE_AES192,
            KeySize::AES256 => KEY_SIZE_AES256,
        }
    }

    pub fn expanded_word_size(&self) -> usize {
        let byte_size = match self {
            KeySize::AES128 => EXPANDED_KEY_SIZE_AES128,
            KeySize::AES192 => EXPANDED_KEY_SIZE_AES192,
            KeySize::AES256 => EXPANDED_KEY_SIZE_AES256,
        };
        byte_size / WORD_SIZE
    }

    pub fn expansion_round_word_width(&self) -> usize {
        match self {
            KeySize::AES128 => ROUND_WORDS_AES128,
            KeySize::AES192 => ROUND_WORDS_AES192,
            KeySize::AES256 => ROUND_WORDS_AES256,
        }
    }

    pub fn encryption_rounds(&self) -> usize {
        match self {
            KeySize::AES128 => ENCRYPTION_ROUNDS_AES128,
            KeySize::AES192 => ENCRYPTION_ROUNDS_AES192,
            KeySize::AES256 => ENCRYPTION_ROUNDS_AES256,
        }
    }
}

impl Default for KeySize {
    fn default() -> Self {
        Self::AES128
    }
}
