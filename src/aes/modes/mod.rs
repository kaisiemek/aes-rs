mod cbc;
mod cfb;
mod common;
mod ecb;
mod ofb;
mod tests;

use crate::aes::{config::AESConfig, datastructures::block::Block};

#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum OperationMode {
    ECB,
    CBC { iv: Block },
    OFB { iv: Block },
    CFB { iv: Block, seg_size: CFBSegmentSize },
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum CFBSegmentSize {
    Bit128,
    Bit8,
}

pub fn encrypt(plaintext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    match config.mode {
        OperationMode::ECB => ecb::encrypt(plaintext, config),
        OperationMode::CBC { iv: _ } => cbc::encrypt(plaintext, config),
        OperationMode::OFB { iv: _ } => ofb::encrypt(plaintext, config),
        OperationMode::CFB { iv: _, seg_size: _ } => cfb::encrypt(plaintext, config),
    }
}

pub fn decrypt(ciphertext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    match config.mode {
        OperationMode::ECB => ecb::decrypt(ciphertext, config),
        OperationMode::CBC { iv: _ } => cbc::decrypt(ciphertext, config),
        OperationMode::OFB { iv: _ } => ofb::decrypt(ciphertext, config),
        OperationMode::CFB { iv: _, seg_size: _ } => cfb::decrypt(ciphertext, config),
    }
}
