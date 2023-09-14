use core::fmt;

use super::{
    constants::{BLOCK_SIZE, COL_SIZE, MIX_COL_MATRIX_DATA, ROW_SIZE, S_BOXES},
    gf_math::{self},
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

    pub fn get_data(&self) -> [u8; BLOCK_SIZE] {
        // restore byte order
        swap_rows_and_cols(&self.data)
    }

    // print inner state of the AES block
    pub fn print_state(&self) {
        for row in 0..ROW_SIZE {
            self[row].iter().for_each(|byte| print!("{:#04X} ", byte));
            println!("");
        }
    }

    pub fn substitute(&mut self) {
        for byte in self.data.iter_mut() {
            *byte = S_BOXES[*byte as usize];
        }
    }

    pub fn shift_rows(&mut self) {
        // shift row 0 by 4(0), row 1 by 3, row 2 by 2 and row 3 by 1 to the right
        for row in 1..ROW_SIZE {
            let shift_amount = ROW_SIZE - row;
            self.shift_row(row, shift_amount);
        }
    }

    pub fn mix_columns(&mut self) {
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
        let mut str = String::new();
        let mut byte_printed = 0;

        // print output in the expected byte order
        for byte in self.get_data() {
            str.push_str(&format!("{:02x}", byte));
            byte_printed += 1;
            if byte_printed == 4 {
                str.push_str(" ");
                byte_printed = 0;
            }
        }
        str.pop();

        write!(f, "{}", str)
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
