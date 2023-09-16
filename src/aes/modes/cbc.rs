use super::common::{get_next_block, xor_blocks};
use crate::aes::{
    block::{ops::AESOperation, AESBlock},
    constants::BLOCK_SIZE,
    key::Key,
    modes::common::remove_padding,
};
use std::array::TryFromSliceError;

pub fn encrypt(plaintext: &[u8], key: Key, iv: &[u8; BLOCK_SIZE]) -> Vec<u8> {
    let enc_schedule = AESOperation::encryption_scheme(key.key_size);

    let mut block = AESBlock::new(key);
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    let mut padded = false;
    let mut previous_block = iv.as_slice();
    let mut current_block: [u8; 16];

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        (current_block, padded) = get_next_block(chunk);
        current_block = xor_blocks(current_block, previous_block);

        block.set_data(current_block);
        block.execute(&enc_schedule);

        ciphertext.extend(block.get_data());
        previous_block = &ciphertext[ciphertext.len() - BLOCK_SIZE..];
    }

    // Pad the last block if no padding was applied
    if !padded {
        let (mut padded_block, _) = get_next_block(&[]);
        padded_block = xor_blocks(padded_block, previous_block);

        block.set_data(padded_block);
        block.execute(&enc_schedule);
        ciphertext.extend_from_slice(&block.get_data());
    }

    ciphertext
}

pub fn decrypt(ciphertext: &[u8], key: Key, iv: &[u8; BLOCK_SIZE]) -> Result<Vec<u8>, String> {
    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err(format!(
            "invalid ciphertext length, must be a multiple of 16 bytes, got: {}",
            ciphertext.len()
        ));
    }

    let dec_schedule = AESOperation::decryption_scheme(key.key_size);

    let mut block = AESBlock::new(key);
    let mut cleartext = Vec::with_capacity(ciphertext.len());

    let mut previous_block = iv.as_slice();
    let mut current_block: [u8; 16];

    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        current_block = chunk
            .try_into()
            .map_err(|err: TryFromSliceError| err.to_string())?;

        block.set_data(current_block);
        block.execute(&dec_schedule);

        let decrypted_block = block.get_data();
        cleartext.extend(xor_blocks(decrypted_block, previous_block));

        previous_block = &ciphertext[cleartext.len() - BLOCK_SIZE..cleartext.len()];
    }

    remove_padding(cleartext)
}
