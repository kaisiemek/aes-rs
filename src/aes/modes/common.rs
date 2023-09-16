use crate::aes::constants::{BLOCK_SIZE, PADDING_BYTE, PADDING_MARKER};

pub fn get_next_block(data: &[u8]) -> ([u8; BLOCK_SIZE], bool) {
    let padded = data.len() < BLOCK_SIZE;

    if !padded {
        return (data.try_into().unwrap(), padded);
    }

    let mut data = data.to_vec();
    data.push(PADDING_MARKER);

    while data.len() != BLOCK_SIZE {
        data.push(PADDING_BYTE);
    }

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

pub fn xor_blocks(mut block: [u8; BLOCK_SIZE], previous: &[u8]) -> [u8; BLOCK_SIZE] {
    block
        .iter_mut()
        .zip(previous.iter())
        .for_each(|(block_byte, previous_byte)| {
            *block_byte ^= *previous_byte;
        });

    block
}
