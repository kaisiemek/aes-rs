pub mod ops;

use self::ops::AESOperation;
use crate::aes::{constants::BLOCK_SIZE, key::Key};

pub struct AESConfig {
    pub key: Key,
    pub mode: OperationMode,
    pub enc_schedule: Vec<AESOperation>,
    pub dec_schedule: Vec<AESOperation>,
}

#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum OperationMode {
    ECB,
    CBC {
        iv: [u8; BLOCK_SIZE],
    },
    CFB {
        iv: [u8; BLOCK_SIZE],
        seg_size: CFBSegmentSize,
    },
    OFB {
        iv: [u8; BLOCK_SIZE],
    },
    CTR {
        iv: [u8; BLOCK_SIZE],
    },
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum CFBSegmentSize {
    Bit128,
    Bit8,
}

impl AESConfig {
    pub fn new(key: Key, mode: OperationMode) -> Self {
        let key_size = key.key_size;

        Self {
            key,
            mode,
            enc_schedule: AESOperation::encryption_scheme(key_size),
            dec_schedule: AESOperation::decryption_scheme(key_size),
        }
    }
}
