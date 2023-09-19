use crate::aes::{
    config::AESConfig,
    datastructures::block::Block,
    modes::{common::encrypt_block, CFBSegmentSize, OperationMode},
};

// TODO: make this prettier, check if vec conversions can be avoided
pub fn encrypt(plaintext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    let (iv, seg_size) = ensure_cfb_mode(config)?;
    let chunk_size = get_chunk_size(seg_size);

    let mut block: Block;
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut previous_ciphertext_block = iv.bytes().to_vec();

    for chunk in plaintext.chunks(chunk_size) {
        let cleartext_segment = chunk.to_vec();
        let input = previous_ciphertext_block.clone();

        block = input.try_into()?;
        block = encrypt_block(block, config);

        let output = block.bytes().to_vec();
        let ciphertext_segment = xor_partial_blocks(cleartext_segment, &output);
        ciphertext.extend_from_slice(&ciphertext_segment);

        match seg_size {
            CFBSegmentSize::Bit128 => previous_ciphertext_block = ciphertext_segment,
            CFBSegmentSize::Bit8 => {
                previous_ciphertext_block[0] = ciphertext_segment[0];
                previous_ciphertext_block.rotate_left(1);
            }
        }
    }

    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    let (iv, seg_size) = ensure_cfb_mode(config)?;
    let chunk_size = get_chunk_size(seg_size);

    let mut block: Block;
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut previous_ciphertext_block = iv.bytes().to_vec();

    for chunk in ciphertext.chunks(chunk_size) {
        let ciphertext_segment = chunk.to_vec();
        let input = previous_ciphertext_block.clone();

        block = input.try_into()?;
        block = encrypt_block(block, config);

        let mut output = block.bytes().to_vec();
        output.truncate(ciphertext_segment.len());
        let cleartext_segment = xor_partial_blocks(output, &ciphertext_segment);
        plaintext.extend_from_slice(&cleartext_segment);

        match seg_size {
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

fn ensure_cfb_mode(config: &AESConfig) -> Result<(Block, CFBSegmentSize), String> {
    match config.mode {
        OperationMode::CFB { iv, seg_size } => Ok((iv, seg_size)),
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
