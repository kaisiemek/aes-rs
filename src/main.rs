mod aes;

use crate::aes::{block::AESBlock, key::Key128};

fn main() {
    let data = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15,
    ];

    let mut block = AESBlock::new(&data);
    block.print_state();
    println!("{}", block);

    block.substitute();
    println!("{}", block);

    block.shift_rows();
    println!("{}", block);

    block.mix_columns();
    println!("{}", block);

    let mut key = Key128::new(data);
    key.expand_key();
    println!("{}", key);

    let round_key = &key[10];
    println!("{}", round_key);
}
