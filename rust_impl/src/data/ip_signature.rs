pub static IPV4_REGEX: &str =
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b";

pub const PRIVATE_IP_PREFIXES: &[&str] = &[
    // RFC 1918 private ranges
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    // Loopback range (127.0.0.1 is also in LOCAL_IPS below, rest covered here)
    "127.",
    // Link-local (RFC 3927) — commonly seen as APIPA addresses and version quads
    "169.254.",
    // Multicast (RFC 5771)
    "224.",
    "225.",
    "226.",
    "227.",
    "228.",
    "229.",
    "230.",
    "231.",
    "232.",
    "233.",
    "234.",
    "235.",
    "236.",
    "237.",
    "238.",
    "239.",
    // Reserved / broadcast
    "240.",
    "255.",
    // Documentation ranges (RFC 5737) — 192.0.2.x, 198.51.100.x, 203.0.113.x
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
];

pub const LOCAL_IPS: &[&str] = &[
    "127.0.0.1",
    "0.0.0.0",
];