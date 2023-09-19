use crate::aes::key::size::KeySize;
use std::fmt;

pub enum AESOperation {
    SubBytes,
    ShiftRows,
    MixColumns,
    AddRoundKey(usize),
    InverseSubBytes,
    InverseShiftRows,
    InverseMixColumn,
}

impl AESOperation {
    pub fn invert(&self) -> Self {
        match self {
            AESOperation::SubBytes => AESOperation::InverseSubBytes,
            AESOperation::ShiftRows => AESOperation::InverseShiftRows,
            AESOperation::MixColumns => AESOperation::InverseMixColumn,
            AESOperation::AddRoundKey(round) => AESOperation::AddRoundKey(*round),
            AESOperation::InverseSubBytes => AESOperation::SubBytes,
            AESOperation::InverseShiftRows => AESOperation::ShiftRows,
            AESOperation::InverseMixColumn => AESOperation::MixColumns,
        }
    }

    pub fn encryption_scheme(key_size: KeySize) -> Vec<Self> {
        let encryption_rounds = key_size.encryption_rounds();
        let mut operations = Vec::with_capacity((encryption_rounds + 1) * 4);

        // before first round: add initial key
        operations.push(AESOperation::AddRoundKey(0));

        // rounds 1 to n-1
        for round in 1..encryption_rounds {
            operations.push(AESOperation::SubBytes);
            operations.push(AESOperation::ShiftRows);
            operations.push(AESOperation::MixColumns);
            operations.push(AESOperation::AddRoundKey(round));
        }

        // last round, no mix columns
        operations.push(AESOperation::SubBytes);
        operations.push(AESOperation::ShiftRows);
        operations.push(AESOperation::AddRoundKey(encryption_rounds));

        operations
    }

    pub fn decryption_scheme(key_size: KeySize) -> Vec<Self> {
        let operations = Self::encryption_scheme(key_size);
        operations.iter().rev().map(|op| op.invert()).collect()
    }
}

impl fmt::Display for AESOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AESOperation::SubBytes => write!(f, "subbytes:    \t"),
            AESOperation::ShiftRows => write!(f, "shiftrows:   \t"),
            AESOperation::MixColumns => write!(f, "mixcols:     \t"),
            AESOperation::AddRoundKey(round) => write!(f, "key {:02}:      \t", round),
            AESOperation::InverseSubBytes => write!(f, "invsubbytes: \t"),
            AESOperation::InverseShiftRows => write!(f, "invshiftrows:\t"),
            AESOperation::InverseMixColumn => write!(f, "invmixcols:  \t"),
        }
    }
}
