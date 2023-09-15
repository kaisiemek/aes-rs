use crate::aes::constants::{KEY_ROUND_CONSTANTS, S_BOXES};
use std::array::TryFromSliceError;

#[derive(Clone, Copy, Default)]
pub struct Word {
    pub data: [u8; 4],
}

impl Word {
    pub fn rot_word(mut self) -> Self {
        let mut rotated_data = self.data.to_vec();
        rotated_data.rotate_left(1);
        self.data.copy_from_slice(&rotated_data);

        self
    }

    pub fn sub_word(mut self) -> Self {
        self.data = self
            .data
            .into_iter()
            .map(|byte| S_BOXES[byte as usize])
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        self
    }

    pub fn apply_rcon(mut self, round: usize) -> Self {
        self.data[0] ^= KEY_ROUND_CONSTANTS[round - 1];
        self
    }
}

impl From<[u8; 4]> for Word {
    fn from(value: [u8; 4]) -> Self {
        Self { data: value }
    }
}

impl TryFrom<&[u8]> for Word {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            data: value.try_into()?,
        })
    }
}

impl std::ops::BitXor for Word {
    type Output = Word;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self {
            data: self
                .data
                .iter()
                .zip(rhs.data.iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        }
    }
}
