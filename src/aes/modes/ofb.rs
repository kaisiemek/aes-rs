use crate::aes::{
    config::AESConfig,
    constants::BLOCK_SIZE,
    datastructures::block::Block,
    modes::{common::encrypt_block, OperationMode},
};

pub fn encrypt(plaintext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    let iv = ensure_ofb_mode(config)?;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut previous_output = iv;
    let mut current_block: Vec<u8>;

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        current_block = chunk.to_vec();
        previous_output = encrypt_block(previous_output, config);
        xor_partial_blocks(&mut current_block, &previous_output.bytes());
        ciphertext.extend(current_block);
    }

    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    encrypt(ciphertext, config)
}

fn xor_partial_blocks(block: &mut [u8], previous: &[u8]) {
    block
        .iter_mut()
        .zip(previous.iter())
        .for_each(|(block_byte, previous_byte)| {
            *block_byte ^= *previous_byte;
        });
}

fn ensure_ofb_mode(config: &AESConfig) -> Result<Block, String> {
    match config.mode {
        OperationMode::OFB { iv } => Ok(iv),
        _ => Err(format!(
            "Invalid operation mode, expected OFB, got {:?}",
            config.mode
        )),
    }
}
