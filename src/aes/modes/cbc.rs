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
    let iv = ensure_cbc_mode(config)?;

    let mut buf: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut block_bytes_read;
    let mut total_bytes_written = 0;

    let mut plaintext_block: Block;
    let mut ciphertext_block: Block;
    let mut input_block: Block;
    let mut previous_block = iv;

    loop {
        block_bytes_read = read_data(plaintext, &mut buf)?;
        if block_bytes_read != BLOCK_SIZE {
            break;
        }

        plaintext_block = buf.into();
        input_block = plaintext_block ^ previous_block;
        ciphertext_block = encrypt_block(input_block, &config.key);
        previous_block = ciphertext_block;

        total_bytes_written += write_data(ciphertext, &ciphertext_block.bytes(), block_bytes_read)?;
    }

    plaintext_block = pad_buffer(buf, block_bytes_read);
    input_block = plaintext_block ^ previous_block;
    ciphertext_block = encrypt_block(input_block, &config.key);
    total_bytes_written += write_data(ciphertext, &ciphertext_block.bytes(), BLOCK_SIZE)?;

    Ok(total_bytes_written)
}

pub fn decrypt(
    ciphertext: &mut impl std::io::Read,
    plaintext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    let iv = ensure_cbc_mode(config)?;

    let mut buf = [0; BLOCK_SIZE];
    let mut total_bytes_written = 0;
    let mut block_bytes_read;

    let mut plaintext_block: Block;
    let mut ciphertext_block: Block;
    let mut output_block: Block;
    let mut previous_block = iv;

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
        output_block = decrypt_block(ciphertext_block, &config.key);
        plaintext_block = output_block ^ previous_block;
        write_queue.push_front(plaintext_block);

        previous_block = ciphertext_block;
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

fn ensure_cbc_mode(config: &AESConfig) -> Result<Block, String> {
    match config.mode {
        OperationMode::CBC { iv } => Ok(iv.into()),
        _ => Err(format!(
            "Invalid operation mode, expected CBC, got {:?}",
            config.mode
        )),
    }
}
