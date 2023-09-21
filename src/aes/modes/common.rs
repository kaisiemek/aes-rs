use crate::aes::{
    config::{ops::AESOperation, AESConfig},
    constants::{BLOCK_SIZE, PADDING_BYTE, PADDING_MARKER},
    datastructures::{block::Block, colmat::ColMatrix},
    key::Key,
};

pub fn encrypt_block(block: Block, config: &AESConfig) -> Block {
    let colmat = ColMatrix::new(block);
    run_block_operations(colmat, &config.enc_schedule, &config.key).block()
}

pub fn decrypt_block(block: Block, config: &AESConfig) -> Block {
    let colmat = ColMatrix::new(block);
    run_block_operations(colmat, &config.dec_schedule, &config.key).block()
}

pub fn read_data(src: &mut impl std::io::Read, buf: &mut [u8]) -> Result<usize, String> {
    src.read(buf).map_err(|err| err.to_string())
}

pub fn write_data(
    dst: &mut impl std::io::Write,
    buf: &[u8],
    bytes: usize,
) -> Result<usize, String> {
    dst.write(&buf[0..bytes]).map_err(|err| err.to_string())
}

pub fn pad_buffer(mut buf: [u8; BLOCK_SIZE], start_index: usize) -> Block {
    buf[start_index..].fill(PADDING_BYTE);
    buf[start_index] = PADDING_MARKER;
    buf.into()
}

pub fn unpad_block(block: Block) -> Result<Vec<u8>, String> {
    let mut block = block.bytes().to_vec();
    for (rev_index, byte) in block.iter().rev().enumerate() {
        if *byte == PADDING_BYTE {
            continue;
        } else if *byte == PADDING_MARKER {
            block.truncate(block.len() - rev_index - 1);
            break;
        } else {
            return Err(format!("Invalid padding byte: {:#04x}", byte));
        }
    }

    Ok(block)
}

fn run_block_operations(
    mut colmat: ColMatrix,
    operations: &[AESOperation],
    key: &Key,
) -> ColMatrix {
    operations.iter().for_each(|op| match op {
        AESOperation::SubBytes => colmat.sub_bytes(),
        AESOperation::ShiftRows => colmat.shift_rows(),
        AESOperation::MixColumns => colmat.mix_columns(),
        AESOperation::AddRoundKey(round) => colmat += key[*round],
        AESOperation::InverseSubBytes => colmat.inv_sub_bytes(),
        AESOperation::InverseShiftRows => colmat.inv_shift_rows(),
        AESOperation::InverseMixColumn => colmat.inv_mix_columns(),
    });

    colmat
}
