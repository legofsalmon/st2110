//! Just enough HTTP/1.1 to serve the router page, its API and the demo facility: one
//! request per connection, with limits on what a request may hold.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// The most a request line and its headers may hold.
const HEAD_LIMIT: usize = 16 << 10;

/// The most a request body may hold: a salvo of a few hundred connections, or an IS-05
/// bulk request.
const BODY_LIMIT: usize = 1 << 20;

/// How long a client may take to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A request, as read.
pub(crate) struct Request {
    pub method: String,
    /// The path, without the query.
    pub path: String,
    /// The query, without the `?`.
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first header of this name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// A query parameter, decoded.
    pub fn param(&self, name: &str) -> Option<String> {
        self.query.split('&').filter_map(|pair| pair.split_once('=')).find(|(n, _)| *n == name).map(|(_, v)| decode(v))
    }
}

/// Decodes `%xx` escapes and `+` in a query value.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => match bytes
                .get(i + 1..i + 3)
                .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok())
            {
                Some(byte) => {
                    out.push(byte);
                    i += 2;
                }
                None => out.push(b'%'),
            },
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A response to send.
pub(crate) struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self { status, content_type: "application/json", headers: Vec::new(), body: value.to_string().into_bytes() }
    }

    /// An error as JSON: `{"error": message}`.
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self::json(status, &serde_json::json!({"error": message.into()}))
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        423 => "Locked",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

/// Reads one request. `Ok(None)` when the client sent nothing, or something that is not
/// an HTTP request.
pub(crate) fn read(stream: &TcpStream) -> io::Result<Option<Request>> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let mut reader = BufReader::new(stream.take(u64::try_from(HEAD_LIMIT + BODY_LIMIT).unwrap_or(u64::MAX)));
    let mut head = 0;
    let mut line = String::new();
    let mut lines = Vec::new();
    loop {
        line.clear();
        let read = reader.by_ref().take((HEAD_LIMIT - head + 1) as u64).read_line(&mut line)?;
        head += read;
        if read == 0 || head > HEAD_LIMIT {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        lines.push(trimmed.to_string());
    }
    let Some((first, rest)) = lines.split_first() else {
        return Ok(None);
    };
    let mut words = first.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (words.next(), words.next(), words.next()) else {
        return Ok(None);
    };
    if !version.starts_with("HTTP/1.") {
        return Ok(None);
    }
    let headers: Vec<(String, String)> = rest
        .iter()
        .filter_map(|h| h.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    let length = match headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("content-length")) {
        Some((_, value)) => match value.parse::<usize>() {
            Ok(length) if length <= BODY_LIMIT => length,
            _ => return Ok(None),
        },
        None => 0,
    };
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Ok(Some(Request { method: method.to_string(), path: path.to_string(), query: query.to_string(), headers, body }))
}

/// Sends a response, and closes the connection.
pub(crate) fn write(mut stream: &TcpStream, response: &Response) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_query_values() {
        assert_eq!(decode("MON%201+video"), "MON 1 video");
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
        assert_eq!(decode("%4"), "%4");
    }
}
