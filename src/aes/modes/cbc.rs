use crate::aes::{
    config::AESConfig,
    constants::BLOCK_SIZE,
    datastructures::block::Block,
    modes::{
        common::{decrypt_block, encrypt_block, get_next_block, remove_padding},
        OperationMode,
    },
};

pub fn encrypt(plaintext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    let iv = ensure_cbc_mode(config)?;
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    let mut was_padded = false;
    let mut previous_block = iv;
    let mut current_block: Block;

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        (current_block, was_padded) = get_next_block(chunk);
        current_block ^= previous_block;
        current_block = encrypt_block(current_block, config);

        ciphertext.extend(current_block.bytes());
        previous_block = current_block;
    }

    // Pad the last block if no padding was applied
    if !was_padded {
        let (mut padded_block, _) = get_next_block(&[]);
        padded_block ^= previous_block;
        padded_block = encrypt_block(padded_block, config);
        ciphertext.extend(padded_block.bytes());
    }

    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    let iv = ensure_cbc_mode(config)?;
    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err(format!(
            "invalid ciphertext length, must be a multiple of 16 bytes, got: {}",
            ciphertext.len()
        ));
    }

    let mut cleartext = Vec::with_capacity(ciphertext.len());

    let mut previous_block = iv;
    let mut current_block: Block;

    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        (current_block, _) = get_next_block(chunk);

        let decrypted_block = decrypt_block(current_block, config);
        let cleartext_block = decrypted_block ^ previous_block;
        cleartext.extend(cleartext_block.bytes());

        previous_block = current_block;
    }

    remove_padding(cleartext)
}

fn ensure_cbc_mode(config: &AESConfig) -> Result<Block, String> {
    match config.mode {
        OperationMode::CBC { iv } => Ok(iv),
        _ => Err(format!(
            "Invalid operation mode, expected CBC, got {:?}",
            config.mode
        )),
    }
}
