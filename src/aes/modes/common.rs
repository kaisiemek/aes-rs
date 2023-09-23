use crate::aes::{
    constants::{BLOCK_SIZE, PADDING_BYTE, PADDING_MARKER},
    datastructures::{block::Block, colmat::ColMatrix},
    key::Key,
};

pub fn encrypt_block(block: Block, key: &Key) -> Block {
    let rounds = key.key_size.encryption_rounds();

    let mut colmat = ColMatrix::new(block);

    // "0"th round: just apply the first block of the inital key
    colmat += key[0];

    for round in 1..rounds {
        colmat.sub_bytes();
        colmat.shift_rows();
        colmat.mix_columns();
        colmat += key[round];
    }

    // last round: do not mix columns
    colmat.sub_bytes();
    colmat.shift_rows();
    colmat += key[rounds];

    colmat.block()
}

pub fn decrypt_block(block: Block, key: &Key) -> Block {
    let rounds = key.key_size.encryption_rounds();

    let mut colmat = ColMatrix::new(block);

    // first round: do not apply inverse mix columns
    colmat += key[rounds];
    colmat.inv_shift_rows();
    colmat.inv_sub_bytes();

    for round in (1..rounds).rev() {
        colmat += key[round];
        colmat.inv_mix_columns();
        colmat.inv_shift_rows();
        colmat.inv_sub_bytes();
    }

    colmat += key[0];

    colmat.block()
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

pub struct Counter {
    block_data: u128,
    counter: u32,
}

impl Counter {
    pub fn new(iv: Block) -> Self {
        let ctr_mask: u128 = 0xffffffff;
        let mut block_data = u128::from(iv);
        let counter = (block_data & ctr_mask) as u32;

        // zero out the space for the counter (32 bit)
        block_data &= !ctr_mask;

        Self {
            block_data,
            counter,
        }
    }

    pub fn increment(&mut self) {
        self.counter = self.counter.wrapping_add(1);
    }

    pub fn get_block(&self) -> Block {
        Block::new(self.block_data | self.counter as u128)
    }
}
