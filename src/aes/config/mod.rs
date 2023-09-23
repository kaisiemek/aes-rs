use crate::aes::{constants::BLOCK_SIZE, key::Key};

pub struct AESConfig {
    pub key: Key,
    pub mode: OperationMode,
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
        Self { key, mode }
    }
}
