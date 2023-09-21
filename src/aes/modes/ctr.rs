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
    let iv = ensure_ctr_mode(config)?;
    let mut ctr = Counter::new(iv);

    let mut buf = [0; BLOCK_SIZE];
    let mut block_bytes_read;
    let mut total_bytes_written = 0;

    let mut input_block: Block;
    let mut output_block: Block;
    let mut ciphertext_block: Block;

    loop {
        block_bytes_read = read_data(plaintext, &mut buf)?;

        if block_bytes_read == 0 {
            break;
        }

        input_block = ctr.get_block();
        output_block = encrypt_block(input_block, config);
        ciphertext_block = output_block ^ buf.as_slice();

        total_bytes_written += write_data(ciphertext, &ciphertext_block.bytes(), block_bytes_read)?;

        ctr.increment();
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

struct Counter {
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

fn ensure_ctr_mode(config: &AESConfig) -> Result<Block, String> {
    match config.mode {
        OperationMode::CTR { iv } => Ok(iv.into()),
        _ => Err(format!(
            "Invalid operation mode, expected CTR, got {:?}",
            config.mode
        )),
    }
}
