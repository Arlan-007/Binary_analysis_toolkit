const MIN_WIDE_STRING_LEN: usize = 6;

pub fn extract_strings(path: &str) -> std::io::Result<Vec<String>> {
    let bytes = std::fs::read(path)?;
    let mut strings = extract_ascii(&bytes);
    strings.extend(extract_utf16(&bytes));
    Ok(strings)
}

fn extract_ascii(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in bytes {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte as char);
        } else {
            if current.len() >= 6 {
                strings.push(current.clone());
            }
            current.clear();
        }
    }

    if current.len() >= 4 {
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
            i += 2;
        } else {
            if current.len() >= MIN_WIDE_STRING_LEN {
                strings.push(current.clone());
            }
            current.clear();
            i += 1;
        }
    }

    if current.len() >= MIN_WIDE_STRING_LEN {
        strings.push(current);
    }
    strings
}
