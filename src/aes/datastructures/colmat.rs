use crate::aes::{
    constants::{
        BLOCK_SIZE, COL_SIZE, INV_MIX_COL_MATRIX, INV_S_BOXES, MIX_COL_MATRIX, ROW_SIZE, S_BOXES,
        WORD_SIZE,
    },
    datastructures::{block::Block, word::Word},
};
use std::{fmt::Display, ops::Mul};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColMatrix {
    block: Block,
}

impl ColMatrix {
    pub fn new(block: Block) -> Self {
        Self { block }
    }

    pub fn block(self) -> Block {
        self.block
    }

    // =================================================================
    //                     AES operations
    // =================================================================

    pub fn sub_bytes(&mut self) {
        self.map_bytes(|byte: u8| S_BOXES[byte as usize]);
    }

    pub fn inv_sub_bytes(&mut self) {
        self.map_bytes(|byte: u8| INV_S_BOXES[byte as usize]);
    }

    pub fn shift_rows(&mut self) {
        // the first row is not shifted
        for row_index in 1..ROW_SIZE {
            let mut row = self.get_row(row_index);
            row <<= row_index;
            self.set_row(row_index, row);
        }
    }

    pub fn inv_shift_rows(&mut self) {
        // the first row is not shifted
        for row_index in 1..ROW_SIZE {
            let mut row = self.get_row(row_index);
            row >>= row_index;
            self.set_row(row_index, row);
        }
    }

    pub fn mix_columns(&mut self) {
        *self *= MIX_COL_MATRIX;
    }

    pub fn inv_mix_columns(&mut self) {
        *self *= INV_MIX_COL_MATRIX;
    }

    // =================================================================
    //                      helper functions
    // =================================================================

    fn get_col(&self, col: usize) -> Word {
        self.block.get_word(col)
    }

    fn get_row(&self, row: usize) -> Word {
        (0..BLOCK_SIZE)
            .skip(row)
            .step_by(ROW_SIZE)
            .map(|byte_index| self.block.get_byte(byte_index))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn set_row(&mut self, row: usize, value: Word) {
        (0..BLOCK_SIZE)
            .skip(row)
            .step_by(ROW_SIZE)
            .zip(value.iter())
            .for_each(|(index, byte)| {
                self.set_byte(index, byte);
            });
    }

    fn set_col(&mut self, col: usize, value: Word) {
        self.block.set_word(col, value);
    }

    fn set_byte(&mut self, index: usize, value: u8) {
        self.block.set_byte(index, value);
    }

    fn map_bytes(&mut self, map_fn: impl Fn(u8) -> u8) {
        self.block = self
            .block
            .iter()
            .map(map_fn)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }
}

impl Display for ColMatrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let words: [Word; 4] = self.block.into();
        let str = words
            .iter()
            .map(|word| word.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        write!(f, "{}", str)
    }
}

impl std::ops::Mul<[Word; 4]> for ColMatrix {
    type Output = Self;

    fn mul(mut self, rhs: [Word; 4]) -> Self::Output {
        for col_index in 0..COL_SIZE {
            let col = self.get_col(col_index);
            let mut new_col_data: [u8; WORD_SIZE] = [0; WORD_SIZE];

            for row_index in 0..ROW_SIZE {
                new_col_data[row_index] = col * rhs[row_index];
            }

            self.set_col(col_index, new_col_data.into());
        }

        self
    }
}

impl std::ops::MulAssign<[Word; 4]> for ColMatrix {
    fn mul_assign(&mut self, rhs: [Word; 4]) {
        *self = self.mul(rhs);
    }
}

impl std::ops::Add<Block> for ColMatrix {
    type Output = ColMatrix;

    fn add(mut self, rhs: Block) -> Self::Output {
        self.block += rhs;
        self
    }
}

impl std::ops::AddAssign<Block> for ColMatrix {
    fn add_assign(&mut self, rhs: Block) {
        self.block += rhs;
    }
}

impl From<[u8; BLOCK_SIZE]> for ColMatrix {
    fn from(bytes: [u8; BLOCK_SIZE]) -> Self {
        ColMatrix::new(Block::from(bytes))
    }
}
