use crate::aes::{
    block::{ops::AESOperation, AESBlock},
    constants::BLOCK_SIZE,
    key::Key,
    modes::common::{get_next_block, remove_padding},
};
use std::array::TryFromSliceError;

pub fn encrypt(plaintext: &[u8], key: Key) -> Result<Vec<u8>, String> {
    let enc_schedule = AESOperation::encryption_scheme(key.key_size);

    let mut block = AESBlock::new(key);
    let mut ciphertext = Vec::new();

    let mut padded = false;
    for chunk in plaintext.chunks(BLOCK_SIZE) {
        let (data, block_padded) = get_next_block(chunk);
        padded = block_padded;
        block.set_data(data);
        block.execute(&enc_schedule);
        ciphertext.extend_from_slice(&block.get_data());
    }

    // Pad the last block if no padding was applied
    if !padded {
        let (data, _) = get_next_block(&[]);
        block.set_data(data);
        block.execute(&enc_schedule);
        ciphertext.extend_from_slice(&block.get_data());
    }

    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], key: Key) -> Result<Vec<u8>, String> {
    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err(format!(
            "invalid ciphertext length, must be a multiple of 16 bytes, got: {}",
            ciphertext.len()
        ));
    }

    let dec_schedule = AESOperation::decryption_scheme(key.key_size);

    let mut block = AESBlock::new(key);
    let mut plaintext = Vec::new();

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
