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
    // Standards bodies and open-source infrastructure
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
    // Major OS / platform vendors
    "microsoft.com",
    "windows.net",
    "microsoftonline.com",
    "azure.com",
    "apple.com",
    // Code hosting and package registries
    "github.com",
    "githubusercontent.com",
    "nuget.org",
    "crates.io",
    // PKI / certificate infrastructure (OCSP, CRL endpoints)
    "digicert.com",
    "letsencrypt.org",
    "verisign.com",
    "globalsign.com",
    "sectigo.com",
    "usertrust.com",
    "comodoca.com",
    // CDN and Google infrastructure frequently embedded via TLS libs
    "google.com",
    "googleapis.com",
    "cloudflare.com",
];