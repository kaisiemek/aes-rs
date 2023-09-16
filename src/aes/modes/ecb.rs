use super::common::{pad_block_data, remove_padding};
use crate::aes::{
    block::{ops::AESOperation, AESBlock},
    constants::BLOCK_SIZE,
    key::Key,
};
use std::array::TryFromSliceError;

pub fn encrypt(plaintext: &[u8], key: Key) -> Vec<u8> {
    let enc_schedule = AESOperation::encryption_scheme(key.key_size);

    let mut block = AESBlock::new(key);
    let mut ciphertext = Vec::new();

    let mut padded = false;
    for chunk in plaintext.chunks(BLOCK_SIZE) {
        let (data, block_padded) = pad_block_data(chunk);
        padded = block_padded;
        block.set_data(data);
        block.execute(&enc_schedule);
        ciphertext.extend_from_slice(&block.get_data());
    }

    // Pad the last block if no padding was applied
    if !padded {
        let (data, _) = pad_block_data(&[]);
        block.set_data(data);
        block.execute(&enc_schedule);
        ciphertext.extend_from_slice(&block.get_data());
    }

    ciphertext
}

pub fn decrypt(ciphertext: &[u8], key: Key) -> Result<Vec<u8>, String> {
    let dec_schedule = AESOperation::decryption_scheme(key.key_size);

    let mut block = AESBlock::new(key);
    let mut plaintext = Vec::new();

    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err(format!(
            "invalid ciphertext length, must be a multiple of 16 bytes, got: {}",
            ciphertext.len()
        ));
    }

    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        block.set_data(
            chunk
                .try_into()
                .map_err(|e: TryFromSliceError| e.to_string())?,
        );
        block.execute(&dec_schedule);
        plaintext.extend_from_slice(&block.get_data());
    }

    remove_padding(plaintext)
}
