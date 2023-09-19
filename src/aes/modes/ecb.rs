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
    ensure_ecb(config)?;

    let mut ciphertext = Vec::new();
    let mut was_padded = false;
    let mut block: Block;

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        (block, was_padded) = get_next_block(chunk);
        ciphertext.extend(encrypt_block(block, config).bytes())
    }

    // Pad the last block if no padding was applied
    if !was_padded {
        let (block, _) = get_next_block(&[]);
        ciphertext.extend(encrypt_block(block, config).bytes());
    }

    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    ensure_ecb(config)?;

    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err(format!(
            "invalid ciphertext length, must be a multiple of 16 bytes, got: {}",
            ciphertext.len()
        ));
    }

    let mut plaintext = Vec::new();
    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        let block = chunk.try_into()?;
        plaintext.extend(decrypt_block(block, config).bytes());
    }

    remove_padding(plaintext)
}

fn ensure_ecb(config: &AESConfig) -> Result<(), String> {
    match config.mode {
        OperationMode::ECB => Ok(()),
        _ => Err(format!(
            "Invalid operation mode, expected ECB, got {:?}",
            config.mode
        )),
    }
}
