mod constants;
mod test;

use self::constants::{AES_IRREDUCIBLE_POLY, INVERSE_LOOKUP_TABLE};

pub fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn gf256_mult(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;

    // russian peasant multiplication algorithm
    while a != 0 && b != 0 {
        // b has a constant term (factor a0) -> add a to p
        if (b & 0x01) != 0 {
            p = gf256_add(a, p);
        }

        let will_exceed_max_degree = (a & 0x80) != 0;

        a <<= 1;

        if will_exceed_max_degree {
            a = gf256_sub(a, AES_IRREDUCIBLE_POLY);
        }

        b >>= 1;
    }

    p
}

pub fn gf256_inv(a: u8) -> u8 {
    INVERSE_LOOKUP_TABLE[a as usize]
}
