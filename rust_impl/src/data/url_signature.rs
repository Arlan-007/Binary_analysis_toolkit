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

pub const BENIGN_URL_HOSTS: &[&str] = &[
    "gnu.org",
    "w3.org",
    "xmlsoap.org",
    "xml.org",
    "openssl.org",
    "python.org",
    "apache.org",
    "mozilla.org",
    "unicode.org",
    "iana.org",
    "ietf.org",
    "sourceware.org",
    "gcc.gnu.org",
    "zlib.net",
    "libpng.org",
    "curl.se",
    "microsoft.com",
    "apple.com",
];