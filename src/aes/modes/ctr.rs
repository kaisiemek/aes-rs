use crate::aes::{
    config::AESConfig,
    constants::BLOCK_SIZE,
    datastructures::block::Block,
    modes::{common::encrypt_block, OperationMode},
};

pub fn encrypt(plaintext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    let iv = ensure_ctr_mode(config)?;
    let mut ctr = Counter::new(iv);

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut current_block: Vec<u8>;

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        current_block = chunk.to_vec();
        let output = encrypt_block(ctr.get_block(), config);
        xor_partial_blocks(&mut current_block, &output.bytes());
        ciphertext.extend(current_block);
        ctr.increment();
    }

    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], config: &AESConfig) -> Result<Vec<u8>, String> {
    encrypt(ciphertext, config)
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

fn xor_partial_blocks(block: &mut [u8], previous: &[u8]) {
    block
        .iter_mut()
        .zip(previous.iter())
        .for_each(|(block_byte, previous_byte)| {
            *block_byte ^= *previous_byte;
        });
}

fn ensure_ctr_mode(config: &AESConfig) -> Result<Block, String> {
    match config.mode {
        OperationMode::CTR { iv } => Ok(iv),
        _ => Err(format!(
            "Invalid operation mode, expected CTR, got {:?}",
            config.mode
        )),
    }
}
