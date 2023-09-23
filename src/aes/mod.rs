pub mod config;
mod constants;
mod datastructures;
pub mod key;
mod modes;

use self::{
    config::{AESConfig, OperationMode},
    datastructures::block::Block,
    key::Key,
    modes::{cbc, cfb, ctr, ecb, gcm, ofb},
};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
};

#[allow(dead_code)]
pub fn encrypt(
    plaintext: &mut impl std::io::Read,
    ciphertext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    match config.mode {
        OperationMode::ECB => ecb::encrypt(plaintext, ciphertext, config),
        OperationMode::CBC { iv: _ } => cbc::encrypt(plaintext, ciphertext, config),
        OperationMode::CFB { iv: _, seg_size: _ } => cfb::encrypt(plaintext, ciphertext, config),
        OperationMode::OFB { iv: _ } => ofb::encrypt(plaintext, ciphertext, config),
        OperationMode::CTR { iv: _ } => ctr::encrypt(plaintext, ciphertext, config),
    }
}

#[allow(dead_code)]
pub fn decrypt(
    ciphertext: &mut impl std::io::Read,
    plaintext: &mut impl std::io::Write,
    config: &AESConfig,
) -> Result<usize, String> {
    match config.mode {
        OperationMode::ECB => ecb::decrypt(ciphertext, plaintext, config),
        OperationMode::CBC { iv: _ } => cbc::decrypt(ciphertext, plaintext, config),
        OperationMode::CFB { iv: _, seg_size: _ } => cfb::decrypt(ciphertext, plaintext, config),
        OperationMode::OFB { iv: _ } => ofb::decrypt(ciphertext, plaintext, config),
        OperationMode::CTR { iv: _ } => ctr::decrypt(ciphertext, plaintext, config),
    }
}

#[allow(dead_code)]
pub fn encrypt_file(
    infile: &std::path::Path,
    outfile: &std::path::Path,
    config: &AESConfig,
) -> Result<usize, String> {
    let infile = File::open(infile).map_err(|err| err.to_string())?;
    let mut instream = BufReader::new(infile);

    let outfile = File::create(outfile).map_err(|err| err.to_string())?;
    let mut outstream = BufWriter::new(outfile);

    encrypt(&mut instream, &mut outstream, config)
}

#[allow(dead_code)]
pub fn decrypt_file(
    infile: &std::path::Path,
    outfile: &std::path::Path,
    config: &AESConfig,
) -> Result<usize, String> {
    let infile = File::open(infile).map_err(|err| err.to_string())?;
    let mut instream = BufReader::new(infile);

    let outfile = File::create(outfile).map_err(|err| err.to_string())?;
    let mut outstream = BufWriter::new(outfile);

    decrypt(&mut instream, &mut outstream, config)
}

#[allow(dead_code)]
pub fn encrypt_vec(input: &Vec<u8>, config: &AESConfig) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(input.len());
    encrypt(&mut input.as_slice(), &mut output, config)?;
    Ok(output)
}

#[allow(dead_code)]
pub fn decrypt_vec(input: &Vec<u8>, config: &AESConfig) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(input.len());
    decrypt(&mut input.as_slice(), &mut output, config)?;
    Ok(output)
}

#[allow(dead_code)]
pub fn authenticated_encrypt_gcm(
    plaintext: &mut impl std::io::Read,
    ciphertext: &mut impl std::io::Write,
    key: &Key,
    iv: &[u8],
    aad: &[u8],
) -> Result<(usize, Block), String> {
    gcm::authenticated_encrypt(plaintext, ciphertext, key, iv, aad)
}

#[allow(dead_code)]
pub fn authenticated_decrypt_gcm(
    ciphertext: &mut impl std::io::Read,
    plaintext: &mut impl std::io::Write,
    key: &Key,
    iv: &[u8],
    aad: &[u8],
    auth_tag: Block,
) -> Result<usize, String> {
    gcm::authenticated_decrypt(ciphertext, plaintext, key, iv, aad, auth_tag)
}
