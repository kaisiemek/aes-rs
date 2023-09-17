use super::CFBSegmentSize;
use crate::aes::{
    block::{ops::AESOperation, AESBlock},
    constants::BLOCK_SIZE,
    key::Key,
};

pub fn encrypt(
    plaintext: &[u8],
    key: Key,
    iv: &[u8; BLOCK_SIZE],
    segment_size: CFBSegmentSize,
) -> Result<Vec<u8>, String> {
    let enc_schedule = AESOperation::encryption_scheme(key.key_size);
    let mut block = AESBlock::new(key);
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut previous_ciphertext_block = iv.to_vec();

    let chunk_size = match segment_size {
        CFBSegmentSize::Bit128 => 128 / 8,
        CFBSegmentSize::Bit8 => 1,
    };

    for chunk in plaintext.chunks(chunk_size) {
        let cleartext_segment = chunk.to_vec();
        let input = previous_ciphertext_block.clone();

        block.set_data(input.try_into().unwrap());
        block.execute(&enc_schedule);

        let output = block.get_data().to_vec();
        let ciphertext_segment = xor_partial_blocks(cleartext_segment, &output);
        ciphertext.extend_from_slice(&ciphertext_segment);

        match segment_size {
            CFBSegmentSize::Bit128 => previous_ciphertext_block = ciphertext_segment,
            CFBSegmentSize::Bit8 => {
                previous_ciphertext_block[0] = ciphertext_segment[0];
                previous_ciphertext_block.rotate_left(1);
            }
        }
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
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut previous_ciphertext_block = iv.to_vec();

    let chunk_size = match segment_size {
        CFBSegmentSize::Bit128 => 128 / 8,
        CFBSegmentSize::Bit8 => 1,
    };

    for chunk in ciphertext.chunks(chunk_size) {
        let ciphertext_segment = chunk.to_vec();
        let input = previous_ciphertext_block.clone();

        block.set_data(input.try_into().unwrap());
        block.execute(&enc_schedule);

        let mut output = block.get_data().to_vec();
        output.truncate(ciphertext_segment.len());
        let cleartext_segment = xor_partial_blocks(output, &ciphertext_segment);
        plaintext.extend_from_slice(&cleartext_segment);

        match segment_size {
            CFBSegmentSize::Bit128 => previous_ciphertext_block = ciphertext_segment,
            CFBSegmentSize::Bit8 => {
                previous_ciphertext_block[0] = ciphertext_segment[0];
                previous_ciphertext_block.rotate_left(1);
            }
        }
    }

    Ok(plaintext)
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
