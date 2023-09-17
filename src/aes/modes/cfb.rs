use crate::aes::{
    block::{ops::AESOperation, AESBlock},
    constants::BLOCK_SIZE,
    key::Key,
};

use super::CFBSegmentSize;

pub fn encrypt(
    plaintext: &[u8],
    key: Key,
    iv: &[u8; BLOCK_SIZE],
    segment_size: CFBSegmentSize,
) -> Result<Vec<u8>, String> {
    let enc_schedule = AESOperation::encryption_scheme(key.key_size);
    let mut block = AESBlock::new(key);
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut previous_ciphertext_block = *iv;

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        let cleartext_segment = chunk.to_vec();
        let input = previous_ciphertext_block;

        block.set_data(input);
        block.execute(&enc_schedule);

        let output = block.get_data();
        let ciphertext_segment = xor_partial_blocks(cleartext_segment, &output);
        ciphertext.extend_from_slice(&ciphertext_segment);

        previous_ciphertext_block = match ciphertext_segment.try_into() {
            Ok(block_data) => block_data,
            Err(_) => {
                break;
            }
        };
    }

    Ok(ciphertext)
}

pub fn decrypt(
    ciphertext: &[u8],
    key: Key,
    iv: &[u8; BLOCK_SIZE],
    segment_size: CFBSegmentSize,
) -> Result<Vec<u8>, String> {
    let enc_schedule = AESOperation::encryption_scheme(key.key_size);
    let mut block = AESBlock::new(key);
    let mut cleartext = Vec::with_capacity(ciphertext.len());
    let mut previous_ciphertext_block = iv.to_vec();

    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        let ciphertext_segment = chunk.to_vec();
        let input = previous_ciphertext_block;

        block.set_data(input.try_into().unwrap());
        block.execute(&enc_schedule);

        let mut output = block.get_data().to_vec();
        output.truncate(ciphertext_segment.len());
        let cleartext_segment = xor_partial_blocks(output, &ciphertext_segment);
        cleartext.extend_from_slice(&cleartext_segment);

        previous_ciphertext_block = ciphertext_segment;
    }

    Ok(cleartext)
}

fn xor_partial_blocks(mut block: Vec<u8>, other: &[u8]) -> Vec<u8> {
    block
        .iter_mut()
        .zip(other.iter())
        .for_each(|(block_byte, other_byte)| {
            *block_byte ^= *other_byte;
        });

    block
}
