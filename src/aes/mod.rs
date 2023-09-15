mod block;
mod constants;
mod gf_math;
pub mod helpers;
pub mod key;
mod tests;

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
