mod aes;

use crate::aes::{block::AESBlock, key::Key128};
use log::LevelFilter;
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();

    let key_data = [
        0x01, 0xd7, 0x04, 0x57, 0x59, 0xce, 0x6e, 0xdf, 0xf4, 0xfd, 0xd1, 0x02, 0x2f, 0x4f, 0x35,
        0x3f,
    ];

    let data = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15,
    ];

    let mut key = Key128::new(key_data);
    key.expand_key();

    let mut block = AESBlock::new(&data);
    println!("{}", block);
    block.encrypt(&key);
    println!("{}", block);

    let data = block.get_data();
    println!(
        "{}",
        data.iter()
            .map(|byte| format!("{:02x}", byte).to_string())
            .collect::<Vec<String>>()
            .join(" ")
    );
}
