use core::fmt;
use std::collections::VecDeque;

use super::{
    constants::{BLOCK_SIZE, COL_SIZE, MIX_COL_MATRIX_DATA, ROW_SIZE, S_BOXES},
    gf_math,
    helpers::{fmt_16_byte_array, swap_rows_and_cols},
    key::{Key128, RoundKey},
};

pub struct AESBlock {
    data: [u8; BLOCK_SIZE],
}

impl AESBlock {
    pub fn new(from: &[u8; BLOCK_SIZE]) -> Self {
        // AES Blocks operate on matrices from column vectors
        Self {
            data: swap_rows_and_cols(from),
        }
    }

    pub fn encrypt(&mut self, key: &Key128) {
        let mut round_keys: VecDeque<&RoundKey> = key.iter().collect();
        let first_key = round_keys.pop_front().unwrap();
        let last_key = round_keys.pop_back().unwrap();

        log::debug!("===== ROUND {} =====", 0);
        log::debug!("input:   \t{}", self);
        self.add_key(first_key);
        log::debug!("key:     \t{}", first_key);
        log::debug!("addkey:  \t{}", self);

        for (i, round_key) in round_keys.iter().enumerate() {
            log::debug!("===== ROUND {} =====", i + 1);
            log::debug!("input:   \t{}", self);
            self.substitute();
            log::debug!("sub:     \t{}", self);
            self.shift_rows();
            log::debug!("shiftrow:\t{}", self);
            self.mix_columns();
            log::debug!("mixcol:  \t{}", self);
            self.add_key(round_key);
            log::debug!("key:     \t{}", round_key);
            log::debug!("addkey:  \t{}", self);
        }

        log::debug!("===== ROUND {} =====", 10);
        log::debug!("input:   \t{}", self);
        self.substitute();
        log::debug!("sub:     \t{}", self);
        self.shift_rows();
        log::debug!("shiftrow:\t{}", self);
        self.add_key(last_key);
        log::debug!("key:     \t{}", last_key);
        log::debug!("addkey:  \t{}", self);
    }

    pub fn get_data(&self) -> [u8; BLOCK_SIZE] {
        swap_rows_and_cols(&self.data)
    }

    #[allow(dead_code)]
    pub fn print_state(&self) {
        for row in 0..ROW_SIZE {
            self[row].iter().for_each(|byte| print!("{:02X} ", byte));
            println!("");
        }
    }

    fn substitute(&mut self) {
        for byte in self.data.iter_mut() {
            *byte = S_BOXES[*byte as usize];
        }
    }

    fn shift_rows(&mut self) {
        // shift row 0 by 4(0), row 1 by 3, row 2 by 2 and row 3 by 1 to the right
        for row in 1..ROW_SIZE {
            let shift_amount = ROW_SIZE - row;
            self.shift_row(row, shift_amount);
        }
    }

    fn mix_columns(&mut self) {
        let mut new_data = [0, 0, 0, 0];

        for col in 0..COL_SIZE {
            let cur_col = self.get_col(col);
            for row in 0..ROW_SIZE {
                let cur_row = MIX_COL_MATRIX_DATA[row];
                new_data[row] = gf_math::vec_mult(&cur_col, &cur_row);
            }
            self.replace_col(col, &new_data);
        }
    }

    // TODO: optimise, do not copy the key data, do index arithmetic instead
    fn add_key(&mut self, key: &RoundKey) {
        let key_column_mat_data = swap_rows_and_cols(key.get_data());

        for (block_byte, key_byte) in self.data.iter_mut().zip(key_column_mat_data.iter()) {
            *block_byte ^= key_byte;
        }
    }

    fn shift_row(&mut self, row: usize, shift_amount: usize) {
        let splice_start = row * ROW_SIZE;

        let (_, right) = self.data.split_at_mut(splice_start);
        let (row, _) = right.split_at_mut(ROW_SIZE);

        let mut rowcpy: Vec<u8> = row.iter().cloned().collect();
        rowcpy.rotate_right(shift_amount);

        row.copy_from_slice(&rowcpy);
    }

    fn get_col(&self, col: usize) -> [u8; 4] {
        let mut col_data = [0, 0, 0, 0];
        for row in 0..ROW_SIZE {
            col_data[row] = self[row][col];
        }
        col_data
    }

    fn replace_col(&mut self, col: usize, col_data: &[u8; COL_SIZE]) {
        for row in 0..ROW_SIZE {
            self[row][col] = col_data[row];
        }
    }
}

impl std::ops::Index<usize> for AESBlock {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        let start = index * ROW_SIZE;
        let end = start + ROW_SIZE;
        &self.data[start..end]
    }
}

impl std::ops::IndexMut<usize> for AESBlock {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let start = index * ROW_SIZE;
        let end = start + ROW_SIZE;
        &mut self.data[start..end]
    }
}

impl fmt::Display for AESBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_16_byte_array(&swap_rows_and_cols(&self.data), f)
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::block::AESBlock;
    use crate::aes::constants::BLOCK_SIZE;
    use crate::aes::key::RoundKey;

    #[test]
    fn test_shift_row() {
        struct TestCase {
            input_data: [u8; BLOCK_SIZE],
            expected_output: String,
        }

        let test_cases = vec![
            TestCase {
                input_data: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
                    0x13, 0x14, 0x15,
                ],
                expected_output: "00051015 04091403 08130207 12010611".to_string(),
            },
            TestCase {
                input_data: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                expected_output: "00000000 00000000 00000000 00000000".to_string(),
            },
            TestCase {
                input_data: [
                    0x00, 0x00, 0x01, 0x01, 0x03, 0x03, 0x07, 0x07, 0x0f, 0x0f, 0x1f, 0x1f, 0x3f,
                    0x3f, 0x7f, 0x7f,
                ],
                expected_output: "00031f7f 030f7f01 0f3f0107 3f00071f".to_string(),
            },
            TestCase {
                input_data: [
                    0x12, 0x22, 0xab, 0xc3, 0xde, 0x12, 0x33, 0x98, 0x75, 0xf7, 0xb2, 0x00, 0xe4,
                    0xe7, 0x60, 0x10,
                ],
                expected_output: "1212b210 def760c3 75e7ab98 e4223300".to_string(),
            },
        ];

        for test_case in test_cases {
            let mut block = AESBlock::new(&test_case.input_data);
            block.shift_rows();
            assert_eq!(block.to_string(), test_case.expected_output);
        }
    }

    #[test]
    fn test_mix_col() {
        struct TestCase {
            input_data: [u8; BLOCK_SIZE],
            expected_output: String,
        }

        let test_cases = vec![
            TestCase {
                input_data: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
                    0x13, 0x14, 0x15,
                ],
                expected_output: "02070005 06030401 0a3b1223 101d161b".to_string(),
            },
            TestCase {
                input_data: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                expected_output: "00000000 00000000 00000000 00000000".to_string(),
            },
            TestCase {
                input_data: [
                    0x00, 0x00, 0x01, 0x01, 0x03, 0x03, 0x07, 0x07, 0x0f, 0x0f, 0x1f, 0x1f, 0x3f,
                    0x3f, 0x7f, 0x7f,
                ],
                expected_output: "00020103 030b070f 0f2f1f3f 3fbf7fff".to_string(),
            },
            TestCase {
                input_data: [
                    0x12, 0x22, 0xab, 0xc3, 0xde, 0x12, 0x33, 0x98, 0x75, 0xf7, 0xb2, 0x00, 0xe4,
                    0xe7, 0x60, 0x10,
                ],
                expected_output: "2a732322 3a371973 5a4dfdda 9181f390".to_string(),
            },
        ];

        for test_case in test_cases {
            let mut block = AESBlock::new(&test_case.input_data);
            block.mix_columns();
            assert_eq!(block.to_string(), test_case.expected_output);
        }
    }

    #[test]
    fn test_key_addition() {
        let block_data = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15,
        ];
        struct TestCase {
            input_key: RoundKey,
            expected_output: String,
        }

        let test_cases = vec![
            TestCase {
                input_key: [0; 16].into(),
                expected_output: "00010203 04050607 08091011 12131415".to_string(),
            },
            TestCase {
                input_key: [0xf0, 0xf0, 0xf0, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into(),
                expected_output: "f0f1f2f3 04050607 08091011 12131415".to_string(),
            },
            TestCase {
                input_key: [0xf0, 0, 0, 0, 0xf0, 0, 0, 0, 0xf0, 0, 0, 0, 0xf0, 0, 0, 0].into(),
                expected_output: "f0010203 f4050607 f8091011 e2131415".to_string(),
            },
            TestCase {
                input_key: [
                    0x01, 0xd7, 0x04, 0x57, 0x59, 0xce, 0x6e, 0xdf, 0xf4, 0xfd, 0xd1, 0x02, 0x2f,
                    0x4f, 0x35, 0x3f,
                ]
                .into(),
                expected_output: "01d60654 5dcb68d8 fcf4c113 3d5c212a".to_string(),
            },
        ];

        for test_case in test_cases {
            let mut block = AESBlock::new(&block_data);
            block.add_key(&test_case.input_key);
            assert_eq!(block.to_string(), test_case.expected_output);
        }
    }
}
