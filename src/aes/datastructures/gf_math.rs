use crate::aes::constants::{
    AES_IRREDUCIBLE_POLY, ENCRYPTION_ROUNDS_AES128, GF256_MULT_02_LOOKUP_TABLE,
    GF256_MULT_03_LOOKUP_TABLE, GF256_MULT_09_LOOKUP_TABLE, GF256_MULT_11_LOOKUP_TABLE,
    GF256_MULT_13_LOOKUP_TABLE, GF256_MULT_14_LOOKUP_TABLE, GHASH_IRREDUCIBLE_POLY,
};

pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn mul(a: u8, b: u8) -> u8 {
    match b {
        1 => a,
        2 => GF256_MULT_02_LOOKUP_TABLE[a as usize],
        3 => GF256_MULT_03_LOOKUP_TABLE[a as usize],
        9 => GF256_MULT_09_LOOKUP_TABLE[a as usize],
        11 => GF256_MULT_11_LOOKUP_TABLE[a as usize],
        13 => GF256_MULT_13_LOOKUP_TABLE[a as usize],
        14 => GF256_MULT_14_LOOKUP_TABLE[a as usize],
        _ => {
            eprintln!(
                "had to perform a manual gf256 multiplication: {:#02x} * {:#02x}",
                a, b
            );
            gf256_mult(a, b)
        }
    }
}

// as described in NIST Special Publication 800-38D, Section 6.3
pub fn ghash_mul(x: u128, mut y: u128) -> u128 {
    let mut out: u128 = 0;
    let mut bit_mask: u128 = 1 << 127;
    let lsb_mask: u128 = 1;

    while bit_mask > 0 {
        // if the i-th bit of x is 1, XOR the out polynomial with the current y
        if (x & bit_mask) > 0 {
            out ^= y;
        }

        let lsb_set = (y & lsb_mask) > 0;

        y >>= 1;

        // in each round divide the y polynomial by the irreducible polynomial if the LSB is 1
        if lsb_set {
            y ^= GHASH_IRREDUCIBLE_POLY;
        }

        bit_mask >>= 1;
    }

    out
}

pub const fn calc_lookup_table(a: u8) -> [u8; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i <= 255 {
        table[i] = gf256_mult(a, i as u8);
        i += 1;
    }

    table
}

pub const fn calc_round_constants() -> [u8; ENCRYPTION_ROUNDS_AES128] {
    let mut rcon = [0; ENCRYPTION_ROUNDS_AES128];
    let mut i = 1;

    rcon[0] = 0x01;

    while i < 10 {
        rcon[i] = rcon[i - 1] << 1;
        if rcon[i - 1] & 0x80 != 0 {
            rcon[i] ^= AES_IRREDUCIBLE_POLY;
        }

        i += 1;
    }

    rcon
}

const fn gf256_mult(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;

    while b != 0 && a != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        // if a exceeds the max degree of an 8-bit polynomial, reduce it by the AES irreducible polynomial
        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= AES_IRREDUCIBLE_POLY;
        }

        b >>= 1;
    }

    result
}
