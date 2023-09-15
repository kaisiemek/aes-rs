use super::{
    constants::{
        BLOCK_SIZE, COL_SIZE, ENCRYPTION_ROUNDS_AES128, MIX_COL_MATRIX, ROW_SIZE, S_BOXES,
    },
    gf_math,
    helpers::{fmt_16_byte_array, swap_rows_and_cols},
    key::{Key128, RoundKey},
};
use core::fmt;
use std::fmt::Display;

pub struct AESBlock {
    data: [u8; BLOCK_SIZE],
    round_keys: Vec<RoundKey>,
}

pub enum AESOperation {
    SubBytes,
    ShiftRows,
    MixColumns,
    AddRoundKey(usize),
    InverseMixColumn,
    InverseShiftRows,
}

impl AESBlock {
    pub fn new(from: &[u8; BLOCK_SIZE], key: Key128) -> AESBlock {
        // AES Blocks operate on matrices from column vectors
        Self {
            data: swap_rows_and_cols(from),
            round_keys: key.iter().collect(),
        }
    }

    pub fn encrypt(&mut self) {
        let encryption_sched = AESOperation::encryption_scheme();
        for operation in encryption_sched.iter() {
            self.run(operation)
        }

        log::info!("ciphertext:\t{}", self);
    }

    pub fn get_data(&self) -> [u8; BLOCK_SIZE] {
        swap_rows_and_cols(&self.data)
    }

    #[allow(dead_code)]
    pub fn print_state(&self) {
        for row in 0..ROW_SIZE {
            self[row].iter().for_each(|byte| print!("{:02X} ", byte));
            println!();
        }
    }

    fn run(&mut self, operation: &AESOperation) {
        match operation {
            AESOperation::SubBytes => self.sub_bytes(),
            AESOperation::ShiftRows => self.shift_rows(),
            AESOperation::MixColumns => self.mix_columns(),
            AESOperation::AddRoundKey(round) => {
                let key = &self.round_keys[*round];
                log::debug!("{} {}", operation, key);
                self.add_key(*round);
                log::debug!("addkey:      \t {}", self);
                if *round < ENCRYPTION_ROUNDS_AES128 {
                    log::debug!("======= ROUND {:02} =======", round + 1);
                }
                return;
            }
            AESOperation::InverseMixColumn => todo!(),
            AESOperation::InverseShiftRows => todo!(),
        }

        log::debug!("{} {}", operation, self);
    }

    fn sub_bytes(&mut self) {
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
                let cur_row = MIX_COL_MATRIX[row];
                new_data[row] = gf_math::vec_mult(&cur_col, &cur_row);
            }
            self.replace_col(col, &new_data);
        }
    }

    // TODO: optimise, do not copy the key data, do index arithmetic instead
    fn add_key(&mut self, round: usize) {
        let key_column_mat_data = swap_rows_and_cols(self.round_keys[round].get_data());

        for (block_byte, key_byte) in self.data.iter_mut().zip(key_column_mat_data.iter()) {
            *block_byte ^= key_byte;
        }
    }

    fn shift_row(&mut self, row: usize, shift_amount: usize) {
        let splice_start = row * ROW_SIZE;

        let (_, right) = self.data.split_at_mut(splice_start);
        let (row, _) = right.split_at_mut(ROW_SIZE);

        let mut rowcpy = row.to_vec();
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

impl AESOperation {
    pub fn invert(&self) -> Self {
        match self {
            AESOperation::SubBytes => AESOperation::SubBytes,
            AESOperation::ShiftRows => AESOperation::InverseShiftRows,
            AESOperation::MixColumns => AESOperation::InverseMixColumn,
            AESOperation::AddRoundKey(round) => AESOperation::AddRoundKey(*round),
            AESOperation::InverseMixColumn => AESOperation::MixColumns,
            AESOperation::InverseShiftRows => AESOperation::ShiftRows,
        }
    }

    pub fn encryption_scheme() -> Vec<Self> {
        let mut operations = vec![];

        // before first round: add initial key
        operations.push(AESOperation::AddRoundKey(0));

        // rounds 1 to n-1
        for round in 1..ENCRYPTION_ROUNDS_AES128 {
            operations.push(AESOperation::SubBytes);
            operations.push(AESOperation::ShiftRows);
            operations.push(AESOperation::MixColumns);
            operations.push(AESOperation::AddRoundKey(round));
        }

        // last round, no mix columns
        operations.push(AESOperation::SubBytes);
        operations.push(AESOperation::ShiftRows);
        operations.push(AESOperation::AddRoundKey(ENCRYPTION_ROUNDS_AES128));

        operations
    }

    pub fn decryption_scheme() -> Vec<Self> {
        let operations = Self::encryption_scheme();
        operations.iter().rev().map(|op| op.invert()).collect()
    }
}

impl Display for AESOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AESOperation::SubBytes => write!(f, "subbytes:    \t"),
            AESOperation::ShiftRows => write!(f, "shiftrows:   \t"),
            AESOperation::MixColumns => write!(f, "mixcols:     \t"),
            AESOperation::AddRoundKey(round) => write!(f, "key {:02}:      \t", round),
            AESOperation::InverseMixColumn => write!(f, "invmixcols:  \t"),
            AESOperation::InverseShiftRows => write!(f, "invshiftrows:\t"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::aes::block::AESBlock;
    use crate::aes::constants::BLOCK_SIZE;
    use crate::aes::key::Key128;

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
            let mut block = AESBlock::new(&test_case.input_data, Default::default());
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
            let mut block = AESBlock::new(&test_case.input_data, Default::default());
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
            input_key: Key128,
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
            let mut block = AESBlock::new(&block_data, test_case.input_key);
            block.add_key(0);
            assert_eq!(block.to_string(), test_case.expected_output);
        }
    }
}
