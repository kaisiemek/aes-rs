use crate::aes::{
    constants::{KEY_ROUND_CONSTANTS, S_BOXES},
    datastructures::gf_math,
};
use std::{
    array::TryFromSliceError,
    fmt::Display,
    ops::{Shl, Shr},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Word(pub u32);

impl Word {
    pub const fn new(word: u32) -> Word {
        Word(word)
    }

    pub fn rotate_right(mut self, bytes: usize) -> Self {
        self.0 = self.0.rotate_right(bytes as u32 * 8);
        self
    }

    pub fn rotate_left(mut self, bytes: usize) -> Self {
        self.0 = self.0.rotate_left(bytes as u32 * 8);
        self
    }

    // =============================================================
    //                  key expansion functions
    // =============================================================
    pub fn rot_word(self) -> Self {
        self.rotate_left(1)
    }

    pub fn sub_word(self) -> Self {
        let mut bytes = self.0.to_be_bytes();
        bytes
            .iter_mut()
            .for_each(|byte| *byte = S_BOXES[*byte as usize]);

        bytes.into()
    }

    pub fn apply_rcon(mut self, round: usize) -> Self {
        let rcon = KEY_ROUND_CONSTANTS[round - 1] as u32;
        self.0 ^= rcon << 24;
        self
    }

    pub fn bytes(self) -> [u8; 4] {
        self.into()
    }

    pub fn iter(self) -> std::array::IntoIter<u8, 4> {
        self.bytes().into_iter()
    }
}

impl From<u32> for Word {
    fn from(value: u32) -> Self {
        Word::new(value)
    }
}

impl From<[u8; 4]> for Word {
    fn from(value: [u8; 4]) -> Self {
        let word = u32::from_be_bytes(value);
        Word::new(word)
    }
}

impl TryFrom<&[u8]> for Word {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let word = u32::from_be_bytes(
            value
                .try_into()
                .map_err(|err: TryFromSliceError| err.to_string())?,
        );
        Ok(Word::new(word))
    }
}

impl TryFrom<Vec<u8>> for Word {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl From<Word> for [u8; 4] {
    fn from(value: Word) -> Self {
        value.0.to_be_bytes()
    }
}

impl Display for Word {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl std::ops::BitXor for Word {
    type Output = Word;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Word::new(self.0 ^ rhs.0)
    }
}

impl std::ops::Mul for Word {
    type Output = u8;

    fn mul(self, rhs: Self) -> Self::Output {
        self.iter()
            .zip(rhs.iter())
            .fold(0, |acc, (a, b)| gf_math::add(acc, gf_math::mul(a, b)))
    }
}

impl std::ops::Shl<usize> for Word {
    type Output = Word;

    fn shl(self, rhs: usize) -> Self::Output {
        self.rotate_left(rhs)
    }
}

impl std::ops::Shr<usize> for Word {
    type Output = Word;

    fn shr(self, rhs: usize) -> Self::Output {
        self.rotate_right(rhs)
    }
}

impl std::ops::ShlAssign<usize> for Word {
    fn shl_assign(&mut self, rhs: usize) {
        *self = self.shl(rhs);
    }
}

impl std::ops::ShrAssign<usize> for Word {
    fn shr_assign(&mut self, rhs: usize) {
        *self = self.shr(rhs);
    }
}
