use std::collections::HashSet;

const MIN_ASCII_STRING_LEN: usize = 6;
const MIN_WIDE_STRING_LEN: usize = 6;

const MAX_STRING_COUNT: usize = 50_000;

pub fn extract_strings(path: &str) -> std::io::Result<Vec<String>> {
    let bytes = std::fs::read(path)?;
    let mut strings = extract_ascii(&bytes);

    let mut seen: HashSet<String> = strings.iter().cloned().collect();
    for s in extract_utf16(&bytes) {
        if seen.insert(s.clone()) {
            strings.push(s);
        }
    }

    strings.truncate(MAX_STRING_COUNT);
    Ok(strings)
}

fn extract_ascii(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in bytes {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte as char);
        } else {
            if current.len() >= MIN_ASCII_STRING_LEN {
                strings.push(current.clone());
            }
            current.clear();
        }
    }

    if current.len() >= MIN_ASCII_STRING_LEN {
        strings.push(current);
    }

    strings
}

fn extract_utf16(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    let mut i = 0;

    while i + 1 < bytes.len() {
        let low = bytes[i];
        let high = bytes[i + 1];

        if (low.is_ascii_graphic() || low == b' ') && high == 0x00 {
            current.push(low as char);
        } else {
            if current.len() >= MIN_WIDE_STRING_LEN {
                strings.push(current.clone());
            }
            current.clear();
        }
        i += 2;
    }

    if current.len() >= MIN_WIDE_STRING_LEN {
        strings.push(current);
    }
    strings
}
