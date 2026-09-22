//! Shared strict parsing and canonical formatting for CLI and state values.

use proof_core::{Address, Digest, Target, Uint256};

pub fn parse_u128(value: &str, name: &str) -> Result<u128, String> {
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(format!("{name} must be an unsigned decimal integer"));
    }

    value
        .parse()
        .map_err(|_| format!("{name} exceeds the supported u128 range"))
}

pub fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(format!("{name} must be an unsigned decimal integer"));
    }

    value
        .parse()
        .map_err(|_| format!("{name} exceeds the supported u64 range"))
}

pub fn parse_decimal_uint256(value: &str, name: &str) -> Result<Uint256, String> {
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(format!("{name} must be an unsigned decimal integer"));
    }

    let mut bytes = [0_u8; 32];
    for digit in value.bytes().map(|byte| byte - b'0') {
        let mut carry = u16::from(digit);
        for byte in bytes.iter_mut().rev() {
            let next = u16::from(*byte) * 10 + carry;
            *byte = next as u8;
            carry = next >> 8;
        }
        if carry != 0 {
            return Err(format!("{name} exceeds the uint256 range"));
        }
    }

    Ok(Uint256::from_be_bytes(bytes))
}

pub fn parse_hex_quantity_uint256(value: &str, name: &str) -> Result<Uint256, String> {
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(format!("{name} must be a 0x-prefixed hexadecimal quantity"));
    };
    if hex.is_empty() || hex.len() > 64 {
        return Err(format!("{name} must fit in a uint256 hexadecimal quantity"));
    }
    if hex.len() > 1 && hex.starts_with('0') {
        return Err(format!(
            "{name} must use canonical hexadecimal quantity encoding"
        ));
    }

    let mut bytes = [0_u8; 32];
    let mut destination = 32 - hex.len().div_ceil(2);
    let raw = hex.as_bytes();
    let mut source = 0;
    if hex.len() % 2 == 1 {
        bytes[destination] = hex_nibble(raw[0])
            .ok_or_else(|| format!("{name} contains a non-hexadecimal character"))?;
        destination += 1;
        source = 1;
    }
    while source < raw.len() {
        let high = hex_nibble(raw[source])
            .ok_or_else(|| format!("{name} contains a non-hexadecimal character"))?;
        let low = hex_nibble(raw[source + 1])
            .ok_or_else(|| format!("{name} contains a non-hexadecimal character"))?;
        bytes[destination] = (high << 4) | low;
        destination += 1;
        source += 2;
    }

    Ok(Uint256::from_be_bytes(bytes))
}

pub fn parse_uint256_word(value: &str, name: &str) -> Result<Uint256, String> {
    parse_hex_exact(value, name).map(Uint256::from_be_bytes)
}

pub fn parse_nonce(value: &str, name: &str) -> Result<Uint256, String> {
    if value.starts_with("0x") {
        return Ok(Uint256::from_be_bytes(parse_hex_exact(value, name)?));
    }

    parse_u128(value, name).map(Uint256::from)
}

pub fn parse_address(value: &str, name: &str) -> Result<Address, String> {
    parse_hex_exact(value, name).map(Address::from_bytes)
}

pub fn parse_digest(value: &str, name: &str) -> Result<Digest, String> {
    parse_hex_exact(value, name).map(Digest::from_bytes)
}

pub fn parse_target(value: &str, name: &str) -> Result<Target, String> {
    parse_hex_exact(value, name).map(Target::from_be_bytes)
}

pub fn hex_string(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn parse_hex_bytes(value: &str, name: &str) -> Result<Vec<u8>, String> {
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(format!("{name} must be 0x-prefixed hexadecimal bytes"));
    };
    if hex.len() % 2 != 0 {
        return Err(format!(
            "{name} must contain an even number of hexadecimal characters"
        ));
    }

    let raw = hex.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let high = hex_nibble(pair[0])
            .ok_or_else(|| format!("{name} contains a non-hexadecimal character"))?;
        let low = hex_nibble(pair[1])
            .ok_or_else(|| format!("{name} contains a non-hexadecimal character"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

pub fn uint256_to_decimal(value: Uint256) -> String {
    let mut bytes = value.to_be_bytes();
    if bytes.iter().all(|byte| *byte == 0) {
        return "0".to_owned();
    }

    let mut digits = Vec::new();
    while bytes.iter().any(|byte| *byte != 0) {
        let mut remainder = 0_u16;
        for byte in &mut bytes {
            let current = (remainder << 8) | u16::from(*byte);
            *byte = (current / 10) as u8;
            remainder = current % 10;
        }
        digits.push(b'0' + remainder as u8);
    }

    digits.into_iter().rev().map(char::from).collect()
}

fn parse_hex_exact<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(format!("{name} must be 0x-prefixed and exactly {N} bytes"));
    };
    if hex.len() != N * 2 {
        return Err(format!("{name} must be 0x-prefixed and exactly {N} bytes"));
    }

    let mut bytes = [0_u8; N];
    let raw = hex.as_bytes();
    for index in 0..N {
        let high = hex_nibble(raw[index * 2])
            .ok_or_else(|| format!("{name} must contain only hexadecimal characters after 0x"))?;
        let low = hex_nibble(raw[index * 2 + 1])
            .ok_or_else(|| format!("{name} must contain only hexadecimal characters after 0x"))?;
        bytes[index] = (high << 4) | low;
    }

    Ok(bytes)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
