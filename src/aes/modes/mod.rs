mod cbc;
mod common;
mod ecb;
mod ofb;
mod tests;

use crate::aes::{constants::BLOCK_SIZE, key::Key};

#[allow(dead_code, clippy::upper_case_acronyms)]
pub enum OperationMode {
    ECB,
    CBC { iv: [u8; BLOCK_SIZE] },
    OFB { iv: [u8; BLOCK_SIZE] },
}

impl OperationMode {
    pub fn encrypt(&self, plaintext: &[u8], key: Key) -> Vec<u8> {
        match self {
            OperationMode::ECB => ecb::encrypt(plaintext, key),
            OperationMode::CBC { iv } => cbc::encrypt(plaintext, key, iv),
            OperationMode::OFB { iv } => ofb::encrypt(plaintext, key, iv),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: Key) -> Result<Vec<u8>, String> {
        match self {
            OperationMode::ECB => ecb::decrypt(ciphertext, key),
            OperationMode::CBC { iv } => cbc::decrypt(ciphertext, key, iv),
            OperationMode::OFB { iv } => ofb::decrypt(ciphertext, key, iv),
        }
    }
}
