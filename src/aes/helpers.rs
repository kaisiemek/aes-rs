use std::fmt;

pub fn fmt_16_byte_array(data: &[u8; 16], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", stringify_16_byte_array(data))
}

pub fn stringify_16_byte_array(data: &[u8; 16]) -> String {
    let word_to_str = |word: &[u8]| -> String {
        word.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join("")
    };

    let block_str = data
        .chunks(4)
        .map(word_to_str)
        .collect::<Vec<String>>()
        .join(" ");

    block_str
}
