pub fn extract_strings(path: &str) -> std::io::Result<Vec<String>> {
    let bytes = std::fs::read(path)?;

    let mut strings = Vec::new();
    let mut current = String::new();

    for byte in bytes {
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

    Ok(strings)
}