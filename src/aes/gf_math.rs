use super::constants::{
    GF256_MULT_02_LOOKUP_TABLE, GF256_MULT_03_LOOKUP_TABLE, GF256_MULT_09_LOOKUP_TABLE,
    GF256_MULT_11_LOOKUP_TABLE, GF256_MULT_13_LOOKUP_TABLE, GF256_MULT_14_LOOKUP_TABLE,
};

pub fn vec_mult(a: &[u8; 4], b: &[u8; 4]) -> u8 {
    a.iter()
        .zip(b.iter())
        .fold(0, |acc, (a, b)| add(acc, mult(*a, *b)))
}

pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn mult(a: u8, b: u8) -> u8 {
    match b {
        1 => a,
        2 => GF256_MULT_02_LOOKUP_TABLE[a as usize],
        3 => GF256_MULT_03_LOOKUP_TABLE[a as usize],
        9 => GF256_MULT_09_LOOKUP_TABLE[a as usize],
        11 => GF256_MULT_11_LOOKUP_TABLE[a as usize],
        13 => GF256_MULT_13_LOOKUP_TABLE[a as usize],
        14 => GF256_MULT_14_LOOKUP_TABLE[a as usize],
        other => panic!(
            "unexpected GF(2^8) value for multiplication: {:#04X}",
            other
        ),
    }
}
