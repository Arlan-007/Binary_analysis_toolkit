#[allow(dead_code)]
pub const URL_PREFIXES: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "ftps://",
];
pub static URL_REGEX: &str =
    r"(https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+";
pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".sh",
];