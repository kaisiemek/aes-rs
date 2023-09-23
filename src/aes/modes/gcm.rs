use crate::aes::{
    constants::BLOCK_SIZE,
    datastructures::block::Block,
    key::Key,
    modes::common::{encrypt_block, read_data, write_data, Counter},
};

pub fn authenticated_encrypt(
    plaintext: &mut impl std::io::Read,
    ciphertext: &mut impl std::io::Write,
    key: &Key,
    iv: &[u8],
    aad: &[u8],
) -> Result<(usize, Block), String> {
    run_authenticated_cipher_operation(plaintext, ciphertext, key, iv, aad, false)
}

pub fn authenticated_decrypt(
    ciphertext: &mut impl std::io::Read,
    plaintext: &mut impl std::io::Write,
    key: &Key,
    iv: &[u8],
    aad: &[u8],
    auth_tag: Block,
) -> Result<usize, String> {
    let (bytes_written, t) =
        run_authenticated_cipher_operation(ciphertext, plaintext, key, iv, aad, true)?;

    if t != auth_tag {
        Err(format!(
            "the authentication tags differed! provided: {} | got: {}",
            auth_tag, t,
        ))
    } else {
        Ok(bytes_written)
    }
}

// GCM core operation, return the generated authentication tag for further processing
// (encrypt: return to caller, decrypt: compare with given tag)
fn run_authenticated_cipher_operation(
    intext: &mut impl std::io::Read,
    outtext: &mut impl std::io::Write,
    key: &Key,
    iv: &[u8],
    aad: &[u8],
    decrypt: bool,
) -> Result<(usize, Block), String> {
    let hash_subkey = generate_hash_subkey(key);
    let j_0 = generate_initial_ctr_block(iv, hash_subkey);

    let mut counter = Counter::new(j_0);
    // save for calculating the authentication tag T later
    let initial_counter_block = counter.get_block();
    // increment once before the first encryption round
    counter.increment();

    let padded_aad = pad_to_multiple_of_128(aad);
    let aad_ghash = ghash(&padded_aad, hash_subkey);
    let aad_len = (aad.len() * 8) as u128;

    let (ghash_value, bytes_written) = gctr(
        intext,
        outtext,
        counter,
        aad_ghash,
        hash_subkey,
        key,
        decrypt,
    )?;

    // bitlength of the ciphertext (same as plaintext)
    let ciphertext_len = (bytes_written * 8) as u128;

    // 64 MSBs: AAD length, 64 LSBs: length of the ciphertext
    let last_ghash_block = Block::new((aad_len << 64) | ciphertext_len);
    let s = next_ghash(ghash_value, last_ghash_block, hash_subkey);
    let t = encrypt_block(initial_counter_block, key) ^ s;

    Ok((bytes_written, t))
}

// as described in NIST Special Publication 800-38D, section 6.4
fn ghash(input: &[Block], hash_subkey: Block) -> Block {
    let mut output = Block::default();

    input.iter().for_each(|next| {
        output = next_ghash(output, *next, hash_subkey);
    });

    output
}

fn next_ghash(current: Block, next: Block, hash_subkey: Block) -> Block {
    (current ^ next) * hash_subkey
}

// as described in NIST Special Publication 800-38D, section 6.5
// main encryption/decryption procedure, very similiar to CTR mode
fn gctr(
    intext: &mut impl std::io::Read,
    outtext: &mut impl std::io::Write,
    mut counter: Counter,
    mut ghash_block: Block,
    hash_subkey: Block,
    key: &Key,
    decrypt: bool,
) -> Result<(Block, usize), String> {
    let mut buf = [0; BLOCK_SIZE];
    let mut block_bytes_read;
    let mut total_bytes_written = 0;

    let mut in_block: Block;
    let mut out_block: Block;
    let mut cipher_input_block: Block;
    let mut cipher_output_block: Block;

    loop {
        block_bytes_read = read_data(intext, &mut buf)?;

        if block_bytes_read == 0 {
            break;
        }

        in_block = buf.into();
        if decrypt {
            if block_bytes_read != BLOCK_SIZE {
                let mut ciphertext_bytes = in_block.bytes();
                ciphertext_bytes[block_bytes_read..].fill(0);
                in_block = ciphertext_bytes.into();
            }
            ghash_block = next_ghash(ghash_block, in_block, hash_subkey);
        }

        cipher_input_block = counter.get_block();
        cipher_output_block = encrypt_block(cipher_input_block, key);
        out_block = cipher_output_block ^ in_block;

        total_bytes_written += write_data(outtext, &out_block.bytes(), block_bytes_read)?;

        if !decrypt {
            if block_bytes_read != BLOCK_SIZE {
                let mut ciphertext_bytes = out_block.bytes();
                ciphertext_bytes[block_bytes_read..].fill(0);
                out_block = ciphertext_bytes.into();
            }
            ghash_block = next_ghash(ghash_block, out_block, hash_subkey);
        }

        counter.increment();
    }

    Ok((ghash_block, total_bytes_written))
}

// =================================================================
//                     helper functions
// =================================================================
fn generate_hash_subkey(key: &Key) -> Block {
    // the hash subkey H is derived from the forward encryption of the 0 block
    let input = Block::new(0);
    encrypt_block(input, key)
}

fn generate_initial_ctr_block(iv: &[u8], hash_subkey: Block) -> Block {
    let mut block_data = [0; BLOCK_SIZE];

    if iv.len() == 96 / 8 {
        block_data[0..iv.len()].copy_from_slice(iv);
        block_data[block_data.len() - 1] = 0x01;

        return block_data.into();
    }

    let mut padded_iv = pad_to_multiple_of_128(iv);
    // 64 MSBs: 0, 64: LSBs length of the iv
    let iv_len = (iv.len() * 8) as u64;
    let last_block = Block::new(iv_len as u128);
    padded_iv.push(last_block);

    ghash(&padded_iv, hash_subkey)
}

fn pad_to_multiple_of_128(data: &[u8]) -> Vec<Block> {
    let mut output = Vec::new();

    for chunk in data.chunks(BLOCK_SIZE) {
        let mut block_data = [0; BLOCK_SIZE];
        if chunk.len() != BLOCK_SIZE {
            block_data[0..chunk.len()].copy_from_slice(chunk);
            output.push(block_data.into());
            break;
        }

        block_data.copy_from_slice(chunk);
        output.push(block_data.into());
    }

    output
}
