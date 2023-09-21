use crate::aes::{
    config::{AESConfig, OperationMode},
    constants::BLOCK_SIZE,
    datastructures::block::Block,
    modes::common::{decrypt_block, encrypt_block, pad_buffer, read_data, unpad_block, write_data},
};
use std::collections::VecDeque;

pub fn encrypt(
    plaintext: &mut impl std::io::Read,
    ciphertext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    ensure_ecb_mode(config)?;

    let mut buf: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut block_bytes_read;
    let mut total_bytes_written = 0;

    let mut plaintext_block: Block;
    let mut ciphertext_block: Block;

    loop {
        block_bytes_read = read_data(plaintext, &mut buf)?;
        if block_bytes_read != BLOCK_SIZE {
            break;
        }

        plaintext_block = buf.into();
        ciphertext_block = encrypt_block(plaintext_block, config);

        total_bytes_written += write_data(ciphertext, &ciphertext_block.bytes(), BLOCK_SIZE)?;
    }

    plaintext_block = pad_buffer(buf, block_bytes_read);
    ciphertext_block = encrypt_block(plaintext_block, config);
    total_bytes_written += write_data(ciphertext, &ciphertext_block.bytes(), BLOCK_SIZE)?;

    Ok(total_bytes_written)
}

pub fn decrypt(
    ciphertext: &mut impl std::io::Read,
    plaintext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    ensure_ecb_mode(config)?;

    let mut buf: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut total_bytes_written = 0;
    let mut block_bytes_read;

    let mut plaintext_block: Block;
    let mut ciphertext_block: Block;

    let mut write_queue: VecDeque<Block> = VecDeque::new();

    loop {
        block_bytes_read = read_data(ciphertext, &mut buf)?;

        if block_bytes_read == 0 {
            break;
        } else if block_bytes_read != BLOCK_SIZE {
            return Err(format!(
                "invalid ciphertext length, the last block was {} long, expected 16 (block size)",
                block_bytes_read
            ));
        }
        ciphertext_block = buf.into();
        plaintext_block = decrypt_block(ciphertext_block, config);
        write_queue.push_front(plaintext_block);

        // Delay writing by one iteration so the padding can be removed from the last block before writing
        if write_queue.len() < 2 {
            continue;
        }

        total_bytes_written += write_data(
            plaintext,
            &write_queue
                .pop_back()
                .ok_or("couldn't fetch a block from the write queue".to_string())?
                .bytes(),
            BLOCK_SIZE,
        )?;
    }

    let last_block = write_queue
        .pop_back()
        .ok_or("couldn't fetch a block from the write queue".to_string())?;
    let unpadded = unpad_block(last_block)?;
    total_bytes_written += write_data(plaintext, &unpadded, unpadded.len())?;

    Ok(total_bytes_written)
}

fn ensure_ecb_mode(config: &AESConfig) -> Result<(), String> {
    match config.mode {
        OperationMode::ECB => Ok(()),
        _ => Err(format!(
            "Invalid operation mode, expected ECB, got {:?}",
            config.mode
        )),
    }
}
