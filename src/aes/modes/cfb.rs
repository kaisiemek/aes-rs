use crate::aes::{
    config::{AESConfig, CFBSegmentSize, OperationMode},
    datastructures::block::Block,
    modes::common::{encrypt_block, read_data, write_data},
};

pub fn encrypt(
    plaintext: &mut impl std::io::Read,
    ciphertext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    let (iv, seg_size) = ensure_cfb_mode(config)?;
    let chunk_size = get_chunk_size(seg_size);

    let mut buf: Vec<u8> = vec![0; chunk_size];
    let mut block_bytes_read;
    let mut total_bytes_written = 0;

    let mut input_block: Block;
    let mut output_block: Block;
    let mut previous_block = iv;

    loop {
        block_bytes_read = read_data(plaintext, &mut buf)?;
        if block_bytes_read == 0 {
            break;
        }

        input_block = previous_block;
        output_block = encrypt_block(input_block, &config.key);

        // ciphertext block = cleartext XOR encrypted block, may be partial
        buf ^= output_block;

        total_bytes_written += write_data(ciphertext, &buf, block_bytes_read)?;

        match seg_size {
            CFBSegmentSize::Bit128 => previous_block = buf.clone().try_into()?,
            CFBSegmentSize::Bit8 => {
                // overwrite the 8 MSBs and then rotate to set the 8 LSBs
                // to those of the current ciphertext block
                previous_block.set_byte(0, buf[0]);
                previous_block <<= 1;
            }
        }
    }

    Ok(total_bytes_written)
}

pub fn decrypt(
    ciphertext: &mut impl std::io::Read,
    plaintext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    let (iv, seg_size) = ensure_cfb_mode(config)?;
    let chunk_size = get_chunk_size(seg_size);

    let mut buf: Vec<u8> = vec![0; chunk_size];
    let mut block_bytes_read;
    let mut total_bytes_written = 0;

    let mut plaintext_block: Block;
    let mut input_block: Block;
    let mut output_block: Block;
    let mut previous_block = iv;

    loop {
        block_bytes_read = read_data(ciphertext, &mut buf)?;
        if block_bytes_read == 0 {
            break;
        }

        input_block = previous_block;
        output_block = encrypt_block(input_block, &config.key);
        plaintext_block = output_block ^ buf.as_slice();

        total_bytes_written += write_data(plaintext, &plaintext_block.bytes(), block_bytes_read)?;

        match seg_size {
            CFBSegmentSize::Bit128 => previous_block = buf.clone().try_into()?,
            CFBSegmentSize::Bit8 => {
                // overwrite the 8 MSBs and then rotate to set the 8 LSBs
                // to those of the current ciphertext block
                previous_block.set_byte(0, buf[0]);
                previous_block <<= 1;
            }
        }
    }

    Ok(total_bytes_written)
}

fn ensure_cfb_mode(config: &AESConfig) -> Result<(Block, CFBSegmentSize), String> {
    match config.mode {
        OperationMode::CFB { iv, seg_size } => Ok((iv.into(), seg_size)),
        _ => Err(format!(
            "Invalid operation mode, expected CFB, got {:?}",
            config.mode
        )),
    }
}

fn get_chunk_size(segment_size: CFBSegmentSize) -> usize {
    match segment_size {
        CFBSegmentSize::Bit128 => 128 / 8,
        CFBSegmentSize::Bit8 => 1,
    }
}
