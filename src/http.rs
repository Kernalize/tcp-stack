//! Day 22 — a minimal HTTP/1.x request parser + responder for the server in `main`.
//!
//! Until now `main` recognised a request by its first bytes (`GET `) and replied on the request
//! line — fine for a single `curl` GET that arrives in one segment, but not real HTTP: it never
//! waited for the full header block, and it always closed after one response. This module does it
//! properly: buffer until the blank line `\r\n\r\n`, parse the request line + the `Connection`
//! header, and decide **keep-alive vs close** per the HTTP/1.0-vs-1.1 rules — so one connection can
//! carry many requests. Everything here is a pure function over bytes, so it is unit-tested offline.
//! Theory: `docs/day22-book.md`.

/// The HTTP version on the request line. It sets the *default* persistence: 1.1 keeps the connection
/// alive unless told otherwise; 1.0 closes unless explicitly asked to persist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
}

/// A parsed HTTP request — only the fields our toy server needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub version: Version,
    /// Whether the connection should persist after this response (RFC 9112 §9.3): HTTP/1.1 defaults
    /// to keep-alive (close only on `Connection: close`); HTTP/1.0 defaults to close (persist only
    /// on `Connection: keep-alive`).
    pub keep_alive: bool,
}

/// Does `buf` contain a complete request head (through the blank line)? Returns the byte length of
/// the head *including* the terminating `\r\n\r\n`, so the caller can drain exactly one request and
/// leave any pipelined bytes behind. `None` while the head is still arriving.
pub fn request_head_len(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Cheap sniff: do these bytes begin a request line we serve? Used to tell an HTTP client from a raw
/// `nc` echo session before we start buffering a head.
pub fn looks_like_request(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 5] = [b"GET ", b"HEAD ", b"POST ", b"PUT ", b"DELETE "];
    METHODS.iter().any(|m| buf.starts_with(m))
}

/// Parse a complete request head (as delimited by [`request_head_len`]). `None` if the request line
/// is malformed. Header parsing is deliberately lenient — we read only `Connection`.
pub fn parse_request(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");

    // Request line: METHOD SP request-target SP HTTP-version
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let version = match parts.next()? {
        "HTTP/1.1" => Version::Http11,
        "HTTP/1.0" => Version::Http10,
        _ => return None,
    };
    if method.is_empty() || path.is_empty() {
        return None;
    }

    // Persistence default by version, overridden by a Connection header (case-insensitive).
    let mut keep_alive = version == Version::Http11;
    for line in lines {
        if line.is_empty() {
            break; // the blank line ends the headers
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("connection") {
                let v = value.trim();
                if v.eq_ignore_ascii_case("close") {
                    keep_alive = false;
                } else if v.eq_ignore_ascii_case("keep-alive") {
                    keep_alive = true;
                }
            }
        }
    }

    Some(Request { method, path, version, keep_alive })
}

/// Build the canned `200 OK` response for a request, with headers consistent with the negotiated
/// persistence: `Connection: keep-alive` (and `HTTP/1.1`) when the connection survives, else
/// `Connection: close`. `Content-Length` is always sent so the peer can frame the body without
/// relying on EOF — essential for keep-alive, where there is no closing FIN to mark the end.
pub fn response(req: &Request) -> Vec<u8> {
    let body = b"Hello from a TCP/IP stack built from scratch in Rust!\n";
    // HEAD must not carry a body, but still advertises the length it would have had.
    let include_body = req.method != "HEAD";
    let (version, conn_hdr) = if req.keep_alive {
        ("HTTP/1.1", "keep-alive")
    } else {
        ("HTTP/1.0", "close")
    };
    let mut resp = format!(
        "{version} 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: {conn_hdr}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    if include_body {
        resp.extend_from_slice(body);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_len_detects_blank_line() {
        assert_eq!(request_head_len(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        // Incomplete: no blank line yet.
        assert_eq!(request_head_len(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        // Pipelined: the length covers only the FIRST head, leaving the rest buffered.
        let two = b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
        let n = request_head_len(two).unwrap();
        assert_eq!(&two[..n], b"GET /a HTTP/1.1\r\n\r\n");
        assert!(request_head_len(&two[n..]).is_some()); // the second request is still there
    }

    #[test]
    fn parses_request_line_and_version() {
        let r = parse_request(b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/index.html");
        assert_eq!(r.version, Version::Http11);
        assert!(r.keep_alive); // HTTP/1.1 defaults to keep-alive
    }

    #[test]
    fn http11_closes_only_on_connection_close() {
        let r = parse_request(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        assert!(!r.keep_alive);
        // Header name is case-insensitive.
        let r2 = parse_request(b"GET / HTTP/1.1\r\nCONNECTION: Close\r\n\r\n").unwrap();
        assert!(!r2.keep_alive);
    }

    #[test]
    fn http10_persists_only_on_keep_alive() {
        let r = parse_request(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert!(!r.keep_alive); // HTTP/1.0 defaults to close
        let r2 = parse_request(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").unwrap();
        assert!(r2.keep_alive);
    }

    #[test]
    fn rejects_malformed_request_line() {
        assert!(parse_request(b"GARBAGE\r\n\r\n").is_none());
        assert!(parse_request(b"GET /\r\n\r\n").is_none()); // no version
        assert!(parse_request(b"GET / HTTP/2.0\r\n\r\n").is_none()); // unsupported version
    }

    #[test]
    fn response_reflects_keep_alive_and_method() {
        let ka = parse_request(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let r = response(&ka);
        let s = String::from_utf8(r).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Connection: keep-alive\r\n"));
        assert!(s.contains("Content-Length: 54\r\n"));
        assert!(s.ends_with("from scratch in Rust!\n"));

        let close = parse_request(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let s2 = String::from_utf8(response(&close)).unwrap();
        assert!(s2.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(s2.contains("Connection: close\r\n"));

        // HEAD advertises Content-Length but sends no body.
        let head = parse_request(b"HEAD / HTTP/1.1\r\n\r\n").unwrap();
        let s3 = String::from_utf8(response(&head)).unwrap();
        assert!(s3.contains("Content-Length: 54\r\n"));
        assert!(s3.ends_with("\r\n\r\n")); // headers only, no body
    }
}
