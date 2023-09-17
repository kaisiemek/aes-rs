use crate::aes::{
    block::{ops::AESOperation, AESBlock},
    constants::BLOCK_SIZE,
    key::Key,
};

pub fn encrypt(plaintext: &[u8], key: Key, iv: &[u8; BLOCK_SIZE]) -> Result<Vec<u8>, String> {
    let enc_schedule = AESOperation::encryption_scheme(key.key_size);
    let mut block = AESBlock::new(key);
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    let mut previous_output = *iv;
    let mut current_block: Vec<u8>;

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        current_block = chunk.to_vec();

        block.set_data(previous_output);
        block.execute(&enc_schedule);
        previous_output = block.get_data();

        xor_partial_blocks(&mut current_block, &previous_output);

        ciphertext.extend(current_block);
    }

    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], key: Key, iv: &[u8; BLOCK_SIZE]) -> Result<Vec<u8>, String> {
    encrypt(ciphertext, key, iv)
}

fn xor_partial_blocks(block: &mut [u8], previous: &[u8]) {
    block
        .iter_mut()
        .zip(previous.iter())
        .for_each(|(block_byte, previous_byte)| {
            *block_byte ^= *previous_byte;
        });
}
