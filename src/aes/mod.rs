mod block;
mod constants;
pub mod helpers;
pub mod key;
pub mod modes;

pub fn encrypt(
    plaintext: &[u8],
    key: key::Key,
    mode: modes::OperationMode,
) -> Result<Vec<u8>, String> {
    mode.encrypt(plaintext, key)
}

pub fn decrypt(
    ciphertext: &[u8],
    key: key::Key,
    mode: modes::OperationMode,
) -> Result<Vec<u8>, String> {
    mode.decrypt(ciphertext, key)
}
