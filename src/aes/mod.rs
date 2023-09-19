pub mod config;
mod constants;
mod datastructures;
pub mod key;
pub mod modes;

use crate::aes::config::AESConfig;

pub fn encrypt(plaintext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    modes::encrypt(plaintext, config)
}

pub fn decrypt(ciphertext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    modes::decrypt(ciphertext, config)
}
