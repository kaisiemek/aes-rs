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

pub fn get_next_block(data: &[u8]) -> (Block, bool) {
    let padded = data.len() < BLOCK_SIZE;

    if !padded {
        return (data.try_into().unwrap(), padded);
    }

    let mut data = data.to_vec();
    data.push(PADDING_MARKER);
    data.resize(BLOCK_SIZE, PADDING_BYTE);

    (data.try_into().unwrap(), padded)
}

pub fn remove_padding(mut data: Vec<u8>) -> Result<Vec<u8>, String> {
    while !data.is_empty() {
        match data.pop() {
            Some(PADDING_BYTE) => continue,
            Some(PADDING_MARKER) => return Ok(data),
            Some(_) => {
                return Err(
                    "invalid padding, encountered non-padding byte before padding marker"
                        .to_string(),
                )
            }
            None => {
                return Err("invalid padding, ran out of data before padding marker".to_string())
            }
        }
    }

    unreachable!()
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
