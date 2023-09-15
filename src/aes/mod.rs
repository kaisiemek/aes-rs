mod block;
mod constants;
mod gf_math;
pub mod helpers;
pub mod key;
mod tests;

use std::array::TryFromSliceError;

use self::{
    block::{AESBlock, AESOperation},
    constants::{BLOCK_SIZE, PADDING_BYTE, PADDING_MARKER},
};

pub fn encrypt(plaintext: &[u8], key: key::Key128) -> Vec<u8> {
    let mut block = AESBlock::new(key);
    let mut ciphertext = Vec::new();

    let enc_schedule = AESOperation::encryption_scheme();
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

pub fn decrypt(ciphertext: &[u8], key: key::Key128) -> Result<Vec<u8>, String> {
    let mut block = AESBlock::new(key);
    let mut plaintext = Vec::new();

    let dec_schedule = AESOperation::decryption_scheme();

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

fn pad_block_data(data: &[u8]) -> ([u8; BLOCK_SIZE], bool) {
    let padded = data.len() < BLOCK_SIZE;

    if !padded {
        return (data.try_into().unwrap(), padded);
    }

    let mut data = data.to_vec();
    data.push(PADDING_MARKER);

    while data.len() != BLOCK_SIZE {
        data.push(PADDING_BYTE);
    }

    (data.try_into().unwrap(), padded)
}

fn remove_padding(mut data: Vec<u8>) -> Result<Vec<u8>, String> {
    while !data.is_empty() {
        match data.pop() {
            Some(PADDING_BYTE) => continue,
            Some(PADDING_MARKER) => return Ok(data),
            Some(_) => {
                return Err(
                    "invalid padding, encountered non-padding byte before padding marker"
                        .to_string(),
                )
            }
            None => {
                return Err("invalid padding, ran out of data before padding marker".to_string())
            }
        }
    }

    unreachable!()
}
