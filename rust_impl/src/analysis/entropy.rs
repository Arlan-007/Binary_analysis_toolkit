pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0usize; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for count in frequencies {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / len;

        entropy -= probability * probability.log2();
    }
    entropy
}
pub fn max_entropy_for_length(len: usize) -> f64 {
    if len <= 1 {
        return 0.0;
    }
    let distinct_cap = len.min(256) as f64;
    distinct_cap.log2()
}