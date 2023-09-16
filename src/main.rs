mod aes;

use crate::aes::{encrypt, key::Key, modes::OperationMode};
use aes::{decrypt, helpers::stringify_16_byte_array};
use log::LevelFilter;
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();

    let key = Key::from([
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ]);

    let plaintext = String::from(
        "this is a very secret message that must never been read by anyone unauthorised: it even has some unicode characters in it: これは日本語の文",
    );

    let ciphertext = encrypt(plaintext.as_bytes(), key.clone(), OperationMode::ECBMode);
    println!("ciphertext");
    ciphertext.chunks(16).for_each(|chunk| {
        println!("{}", stringify_16_byte_array(chunk.try_into().unwrap()));
    });

    let decrypted =
        decrypt(&ciphertext, key.clone(), OperationMode::ECBMode).expect("Decryption failed");
    let plaintext = String::from_utf8(decrypted).expect("String construction failed");
    println!("decrypted: {}", plaintext);
}
