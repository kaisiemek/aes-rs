use crate::aes::{constants::BLOCK_SIZE, datastructures::word::Word};
use std::{array::TryFromSliceError, fmt::Display};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Block(u128);

impl Block {
    pub fn new(block: u128) -> Block {
        Block(block)
    }

    pub fn set_byte(&mut self, index: usize, value: u8) {
        let shift_amount = (128 - 8) - (index * 8);

        let null_mask: u128 = !(0xff << (shift_amount));
        let value = (value as u128) << shift_amount;
        self.0 &= null_mask;
        self.0 |= value;
    }

    pub fn get_byte(&self, index: usize) -> u8 {
        let shift_amount = (128 - 8) - (index * 8);

        let byte_mask: u128 = 0xff << shift_amount;
        let mut value = self.0 & byte_mask;
        value >>= shift_amount;

        value as u8
    }

    pub fn set_word(&mut self, index: usize, value: Word) {
        let shift_amount = (128 - 32) - (index * 32);

        let null_mask: u128 = !(0xffffffff << (shift_amount));
        let value = (value.0 as u128) << shift_amount;
        self.0 &= null_mask;
        self.0 |= value;
    }

    pub fn get_word(&self, index: usize) -> Word {
        let shift_amount = (128 - 32) - (index * 32);

        let word_mask: u128 = 0xffffffff << shift_amount;
        let mut value = self.0 & word_mask;
        value >>= shift_amount;

        Word(value as u32)
    }

    pub fn rotate_left(&mut self, bytes: usize) {
        let mut u128_bytes = self.bytes();
        u128_bytes.rotate_left(bytes);
        self.0 = u128::from_be_bytes(u128_bytes);
    }

    pub fn rotate_right(&mut self, bytes: usize) {
        let mut u128_bytes = self.bytes();
        u128_bytes.rotate_right(bytes);
        self.0 = u128::from_be_bytes(u128_bytes);
    }

    pub fn bytes(self) -> [u8; BLOCK_SIZE] {
        self.0.to_be_bytes()
    }

    pub fn iter(self) -> std::array::IntoIter<u8, 16> {
        self.bytes().into_iter()
    }
}

// =================================================================
//                   arithmetic operations
// =================================================================

impl std::ops::Add for Block {
    type Output = Block;

    // Addition in GF(2^8) is equivalent to the XOR operation
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl std::ops::AddAssign for Block {
    // Addition in GF(2^8) is equivalent to the XOR operation
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        *self ^= rhs;
    }
}

impl std::ops::ShlAssign<usize> for Block {
    fn shl_assign(&mut self, rhs: usize) {
        self.rotate_left(rhs);
    }
}

impl std::ops::ShrAssign<usize> for Block {
    fn shr_assign(&mut self, rhs: usize) {
        self.rotate_right(rhs);
    }
}

impl std::ops::BitXor for Block {
    type Output = Block;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.0 ^= rhs.0;
        self
    }
}

impl std::ops::BitXorAssign for Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl std::ops::BitXor<&Block> for Block {
    type Output = Block;

    fn bitxor(self, rhs: &Block) -> Self::Output {
        self ^ *rhs
    }
}

impl std::ops::BitXorAssign<&Block> for Block {
    fn bitxor_assign(&mut self, rhs: &Block) {
        *self ^= *rhs;
    }
}

// allow partial block XORs
impl std::ops::BitXorAssign<Block> for &mut [u8] {
    fn bitxor_assign(&mut self, rhs: Block) {
        self.iter_mut()
            .zip(rhs.bytes().iter())
            .for_each(|(slice_byte, block_byte)| *slice_byte ^= block_byte);
    }
}

impl std::ops::BitXor<&[u8]> for Block {
    type Output = Block;

    fn bitxor(mut self, rhs: &[u8]) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl std::ops::BitXorAssign<&[u8]> for Block {
    fn bitxor_assign(&mut self, rhs: &[u8]) {
        let mut u128_bytes: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

        let n = std::cmp::min(BLOCK_SIZE, rhs.len());
        u128_bytes[0..n].copy_from_slice(rhs);

        let block = u128::from_be_bytes(u128_bytes);
        self.0 ^= block;
    }
}

impl std::ops::BitXorAssign<Block> for Vec<u8> {
    fn bitxor_assign(&mut self, rhs: Block) {
        self.iter_mut()
            .zip(rhs.bytes().iter())
            .for_each(|(vec_byte, block_byte)| *vec_byte ^= block_byte);
    }
}

// =================================================================
//                      type conversions
// =================================================================

impl From<[u8; 16]> for Block {
    fn from(value: [u8; 16]) -> Self {
        let word = u128::from_be_bytes(value);
        Block::new(word)
    }
}

impl From<[Word; 4]> for Block {
    fn from(value: [Word; 4]) -> Self {
        let bytes = value
            .into_iter()
            .flat_map(|word| word.bytes())
            .collect::<Vec<u8>>();

        bytes.as_slice().try_into().unwrap()
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let block = u128::from_be_bytes(
            value
                .try_into()
                .map_err(|err: TryFromSliceError| err.to_string())?,
        );

        Ok(Block::new(block))
    }
}

impl TryFrom<Vec<u8>> for Block {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl From<Block> for [u8; BLOCK_SIZE] {
    fn from(value: Block) -> Self {
        value.0.to_be_bytes()
    }
}

impl From<Block> for u128 {
    fn from(value: Block) -> Self {
        value.0
    }
}

impl From<Block> for [Word; 4] {
    fn from(value: Block) -> Self {
        value
            .bytes()
            .chunks(4)
            .map(|chunk| Word::try_from(chunk).unwrap())
            .collect::<Vec<Word>>()
            .try_into()
            .unwrap()
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let words: [Word; 4] = (*self).into();
        let str = words
            .iter()
            .map(|word| word.to_string())
            .collect::<Vec<String>>()
            .join(" ");

        write!(f, "{}", str)
    }
}
