mod cbc;
mod cfb;
mod common;
mod ecb;
mod ofb;
mod tests;

use crate::aes::{constants::BLOCK_SIZE, key::Key};

#[allow(dead_code, clippy::upper_case_acronyms)]
pub enum OperationMode {
    ECB,
    CBC {
        iv: [u8; BLOCK_SIZE],
    },
    OFB {
        iv: [u8; BLOCK_SIZE],
    },
    CFB {
        iv: [u8; BLOCK_SIZE],
        seg_size: CFBSegmentSize,
    },
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum CFBSegmentSize {
    Bit128,
    Bit8,
}

impl OperationMode {
    pub fn encrypt(&self, plaintext: &[u8], key: Key) -> Result<Vec<u8>, String> {
        match self {
            OperationMode::ECB => ecb::encrypt(plaintext, key),
            OperationMode::CBC { iv } => cbc::encrypt(plaintext, key, iv),
            OperationMode::OFB { iv } => ofb::encrypt(plaintext, key, iv),
            OperationMode::CFB { iv, seg_size } => cfb::encrypt(plaintext, key, iv, *seg_size),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: Key) -> Result<Vec<u8>, String> {
        match self {
            OperationMode::ECB => ecb::decrypt(ciphertext, key),
            OperationMode::CBC { iv } => cbc::decrypt(ciphertext, key, iv),
            OperationMode::OFB { iv } => ofb::decrypt(ciphertext, key, iv),
            OperationMode::CFB { iv, seg_size } => cfb::decrypt(ciphertext, key, iv, *seg_size),
        }
    }
}
