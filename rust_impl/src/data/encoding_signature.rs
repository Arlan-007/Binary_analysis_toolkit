use base64::{engine::general_purpose, Engine};
use regex::Regex;
use hex;

pub fn decode_base64(s: &str) -> Option<String> {
    let bytes = general_purpose::STANDARD.decode(s).ok()?;

    String::from_utf8(bytes).ok()
}
pub fn is_base64(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }
    if s.len() % 4 != 0 {
        return false;
    }
    let decoded = match general_purpose::STANDARD.decode(s) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    if decoded.is_empty() {
        return false;
    }
    let printable = decoded
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();

    let ratio = printable as f64 / decoded.len() as f64;
    ratio > 0.8
}

pub fn decode_hex(s: &str) -> Option<String> {
    let bytes = hex::decode(s).ok()?;

    String::from_utf8(bytes).ok()
}
pub fn is_hex(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }
    if s.len() % 2 != 0 {
        return false;
    }
    let decoded = match hex::decode(s) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    if decoded.is_empty() {
        return false;
    }
    let printable = decoded
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();

    let ratio = printable as f64 / decoded.len() as f64;
    ratio > 0.8
}