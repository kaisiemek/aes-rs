use crate::aes::constants::{
    ENCRYPTION_ROUNDS_AES128, ENCRYPTION_ROUNDS_AES192, ENCRYPTION_ROUNDS_AES256, KEY_SIZE_AES128,
    KEY_SIZE_AES192, KEY_SIZE_AES256,
};

#[derive(Clone)]
pub enum KeySize {
    AES128,
    AES192,
    AES256,
}

impl KeySize {
    fn byte_size(&self) -> usize {
        match self {
            KeySize::AES128 => KEY_SIZE_AES128,
            KeySize::AES192 => KEY_SIZE_AES192,
            KeySize::AES256 => KEY_SIZE_AES256,
        }
    }

    fn encryption_rounds(&self) -> usize {
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
