pub mod block;
pub mod constants;
mod gf_math;
mod test;

// pub struct Block {
//     pub bytes: [[u8; 4]; 4],
// }

// impl Block {
//     pub fn substitute(&mut self) {
//         self.bytes
//             .iter_mut()
//             .for_each(|byte| *byte = S_BOXES[*byte as usize])
//     }

//     pub fn shift_rows(&mut self) {
//         let mut row_shift = 4;
//         let new_bytes = self.bytes.clone();

//         for i in 0..self.bytes.len() {
//             let row = i / 4;
//             let row_shift = 4 - row; // shift first row
//             let row_index = i % 4;
//         }
//     }

//     // transform the array index into the block byte index and vice versa
//     // blocks are arranged in a 4x4 matrix with the index moving along the columns
//     //    array             block
//     // 00 01 02 03       00 04 08 12
//     // 04 05 06 07  <->  01 05 09 13
//     // 08 09 10 11       02 06 10 14
//     // 12 13 14 15       03 07 11 15
//     fn swap_block_array_indices(&self, index: usize) -> usize {
//         ((index / 4) + (index * 4)) % 16
//     }
// }
