use crate::aes::{
    config::{AESConfig, OperationMode},
    constants::BLOCK_SIZE,
    datastructures::block::Block,
    modes::common::{encrypt_block, read_data, write_data},
};

pub fn encrypt(
    plaintext: &mut impl std::io::Read,
    ciphertext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    let iv = ensure_ofb_mode(config)?;

    let mut buf = [0; BLOCK_SIZE];
    let mut block_bytes_read;
    let mut total_bytes_written = 0;

    let mut plaintext_block: Block;
    let mut ciphertext_block: Block;
    let mut input_block: Block;
    let mut output_block: Block;
    let mut previous_block = iv;

    loop {
        block_bytes_read = read_data(plaintext, &mut buf)?;
        if block_bytes_read == 0 {
            break;
        }

        plaintext_block = buf.into();
        input_block = previous_block;
        output_block = encrypt_block(input_block, config);
        ciphertext_block = plaintext_block ^ output_block;
        previous_block = output_block;

        total_bytes_written += write_data(ciphertext, &ciphertext_block.bytes(), block_bytes_read)?;
    }

    Ok(total_bytes_written)
}

pub fn decrypt(
    ciphertext: &mut impl std::io::Read,
    plaintext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    encrypt(ciphertext, plaintext, config)
}

fn ensure_ofb_mode(config: &AESConfig) -> Result<Block, String> {
    match config.mode {
        OperationMode::OFB { iv } => Ok(iv.into()),
        _ => Err(format!(
            "Invalid operation mode, expected OFB, got {:?}",
            config.mode
        )),
    }
}
