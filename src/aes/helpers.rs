use super::constants::{BLOCK_SIZE, COL_SIZE, ROW_SIZE};
use std::fmt;

pub fn fmt_16_byte_array(data: &[u8; 16], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let word_to_str = |word: &[u8]| -> String {
        word.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join("")
    };

    let key_str = data
        .chunks(4)
        .map(word_to_str)
        .collect::<Vec<String>>()
        .join(" ");

    write!(f, "{}", key_str)
}

// Transform the input data format into a col vector matrix
// 00 01 02 03       00 04 08 12
// 04 05 06 07  -->  01 05 09 13
// 08 09 10 11       02 06 10 14
// 12 13 14 15       03 07 11 15
pub fn swap_rows_and_cols(data: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
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
