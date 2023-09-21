use aes_rs::aes::{
    config::{AESConfig, OperationMode},
    decrypt, decrypt_file, encrypt, encrypt_file,
    key::Key,
};
use std::path::Path;

fn main() -> Result<(), String> {
    let key = Key::from([
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ]);
    let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let config = AESConfig::new(key, OperationMode::OFB { iv });

    encrypt_sample_file(&config)?;
    decrypt_sample_file(&config)?;
    encrypt_decrypt_string(&config)?;

    Ok(())
}

fn encrypt_sample_file(config: &AESConfig) -> Result<usize, String> {
    let infile = Path::new("sample-files/large-doc.pdf");
    let outfile = Path::new("sample-files/large-doc.aes");

    encrypt_file(infile, outfile, config)
}

fn decrypt_sample_file(config: &AESConfig) -> Result<usize, String> {
    let infile = Path::new("sample-files/large-doc.aes");
    let outfile = Path::new("sample-files/large-doc-decrypted.pdf");
    decrypt_file(infile, outfile, config)
}

fn encrypt_decrypt_string(config: &AESConfig) -> Result<(), String> {
    let plaintext = String::from(
        "[secret sample message] (streng geheime Beispielnachricht) 「秘密サンプルメッセージ」 『秘密样本信息』",
    ).into_bytes();

    let mut ciphertext = Vec::new();
    encrypt(&mut plaintext.as_slice(), &mut ciphertext, config)?;

    let mut decrypted_plaintext = Vec::new();
    decrypt(&mut ciphertext.as_slice(), &mut decrypted_plaintext, config)?;
    let plaintext = String::from_utf8(decrypted_plaintext).map_err(|err| err.to_string())?;
    println!("decrypted: {}", plaintext);
    Ok(())
}
