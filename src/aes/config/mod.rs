pub mod ops;

use self::ops::AESOperation;
use super::{key::Key, modes::OperationMode};

pub struct AESConfig {
    pub key: Key,
    pub mode: OperationMode,
    pub enc_schedule: Vec<AESOperation>,
    pub dec_schedule: Vec<AESOperation>,
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
