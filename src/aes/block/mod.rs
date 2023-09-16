pub mod gf_math;
pub mod ops;
mod tests;

use self::ops::AESOperation;
use super::{
    constants::{
        BLOCK_SIZE, COL_SIZE, ENCRYPTION_ROUNDS_AES128, INV_MIX_COL_MATRIX, INV_S_BOXES,
        MIX_COL_MATRIX, ROW_SIZE, S_BOXES,
    },
    helpers::fmt_16_byte_array,
    key::{roundkey::RoundKey, Key},
};
use core::fmt;

pub struct AESBlock {
    data: [u8; BLOCK_SIZE],
    round_keys: Vec<RoundKey>,
}

impl AESBlock {
    pub fn new(key: Key) -> AESBlock {
        // AES Blocks operate on matrices from column vectors
        Self {
            data: Default::default(),
            round_keys: key.iter().collect(),
        }
    }

    pub fn set_data(&mut self, data: [u8; BLOCK_SIZE]) {
        self.data = swap_rows_and_cols(&data);
    }

    pub fn execute(&mut self, schedule: &[AESOperation]) {
        schedule.iter().for_each(|op| self.run(op));
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
            AESOperation::SubBytes => self.sub_bytes(false),
            AESOperation::ShiftRows => self.shift_rows(false),
            AESOperation::MixColumns => self.mix_columns(false),
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
            AESOperation::InverseSubBytes => self.sub_bytes(true),
            AESOperation::InverseShiftRows => self.shift_rows(true),
            AESOperation::InverseMixColumn => self.mix_columns(true),
        }

        log::debug!("{} {}", operation, self);
    }

    fn sub_bytes(&mut self, inverse: bool) {
        let table = if inverse { &INV_S_BOXES } else { &S_BOXES };
        for byte in self.data.iter_mut() {
            *byte = table[*byte as usize];
        }
    }

    fn shift_rows(&mut self, inverse: bool) {
        let shift_amounts = if inverse { [0, 1, 2, 3] } else { [0, 3, 2, 1] };
        // shift row 0 by 4(0), row 1 by 3, row 2 by 2 and row 3 by 1 to the right
        (1..ROW_SIZE).for_each(|row| {
            self.shift_row(row, shift_amounts[row]);
        });
    }

    fn mix_columns(&mut self, inverse: bool) {
        let mut new_data = [0, 0, 0, 0];
        let matrix = if inverse {
            &INV_MIX_COL_MATRIX
        } else {
            &MIX_COL_MATRIX
        };

        for col in 0..COL_SIZE {
            let cur_col = self.get_col(col);
            for row in 0..ROW_SIZE {
                let cur_row = matrix[row];
                new_data[row] = gf_math::vec_mult(&cur_col, &cur_row);
            }
            self.replace_col(col, &new_data);
        }
    }

    fn add_key(&mut self, round: usize) {
        let key_data = self.round_keys[round].get_data();

        for col in 0..COL_SIZE {
            for row in 0..ROW_SIZE {
                let rowmat_index = row * ROW_SIZE + col;
                let colmat_index = col * COL_SIZE + row;
                self.data[colmat_index] ^= key_data[rowmat_index];
            }
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

// Transform the input data format into a col vector matrix
// 00 01 02 03       00 04 08 12
// 04 05 06 07  -->  01 05 09 13
// 08 09 10 11       02 06 10 14
// 12 13 14 15       03 07 11 15
fn swap_rows_and_cols(data: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut swapped = [0; BLOCK_SIZE];
    for col in 0..COL_SIZE {
        for row in 0..ROW_SIZE {
            let new_index = row * ROW_SIZE + col;
            let old_index = col * COL_SIZE + row;
            swapped[new_index] = data[old_index]
        }
    }
    swapped
}
