mod cbc;
mod common;
mod ecb;
mod tests;

use crate::aes::{constants::BLOCK_SIZE, key::Key};

#[allow(dead_code)]
pub enum OperationMode {
    ECBMode,
    CBCMode { iv: [u8; BLOCK_SIZE] },
}

impl OperationMode {
    pub fn encrypt(&self, plaintext: &[u8], key: Key) -> Vec<u8> {
        match self {
            OperationMode::ECBMode => ecb::encrypt(plaintext, key),
            OperationMode::CBCMode { iv } => cbc::encrypt(plaintext, key, iv),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: Key) -> Result<Vec<u8>, String> {
        match self {
            OperationMode::ECBMode => ecb::decrypt(ciphertext, key),
            OperationMode::CBCMode { iv } => cbc::decrypt(ciphertext, key, iv),
        }
    }
}
