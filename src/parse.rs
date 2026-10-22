// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Parsing primitives — **nom only, no regular expressions anywhere**.
//!
//! Everything the daemon has to understand from the outside world is parsed
//! here, so that the rest of the code only ever sees typed values:
//!
//! * HTTP/1.1 status line, headers, chunked bodies ([`parse_head`],
//!   [`decode_chunked`]);
//! * node tags such as `node-02-de-hysteria` → index/geo/protocol
//!   ([`node_tag`]);
//! * `https://…` URLs and `host:port` pairs ([`Url`], [`host_port`]);
//! * `cloudflare` `cdn-cgi/trace` payloads ([`trace_info`]);
//! * `.env` files ([`env_line`]).
//!
//! Why nom instead of hand-rolled `split()` chains: the inputs are
//! attacker-adjacent (a broken/blocked node can answer with anything, including
//! a 2 MiB HTML page instead of JSON). nom gives explicit, testable grammar
//! rules and total functions with no panics on malformed bytes.

use nom::bytes::complete::{tag, take_till, take_while, take_while1, take_while_m_n};
use nom::character::complete::digit1;
use nom::combinator::map_res;
use nom::multi::fold_many0;
use nom::sequence::{preceded, separated_pair, terminated};
use nom::{IResult, Parser};

const CRLF: &[u8] = b"\r\n";

// ---------------------------------------------------------------------------
// Protocols
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Hysteria2,
    VlessReality,
    Vless,
    Tuic,
    WireGuard,
    Shadowsocks,
    Trojan,
    AnyTls,
    Socks,
    Http,
    Direct,
    Other,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Hysteria2 => "hysteria2",
            Protocol::VlessReality => "vless-reality",
            Protocol::Vless => "vless",
            Protocol::Tuic => "tuic",
            Protocol::WireGuard => "wireguard",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Trojan => "trojan",
            Protocol::AnyTls => "anytls",
            Protocol::Socks => "socks",
            Protocol::Http => "http",
            Protocol::Direct => "direct",
            Protocol::Other => "other",
        }
    }

    /// Map a single tag token (or an explicit `protocol:` config value) to a
    /// protocol. Unknown tokens yield `None` so the caller keeps looking.
    pub fn from_token(token: &str) -> Option<Protocol> {
        match token {
            "hysteria2" | "hy2" | "hysteria" => Some(Protocol::Hysteria2),
            "vless" => Some(Protocol::Vless),
            "reality" | "vless-reality" | "vless_reality" | "vless-reality-tcp" => {
                Some(Protocol::VlessReality)
            }
            "tuic" => Some(Protocol::Tuic),
            "wireguard" | "wg" | "awg" | "amneziawg" => Some(Protocol::WireGuard),
            "shadowsocks" | "ss" => Some(Protocol::Shadowsocks),
            "trojan" => Some(Protocol::Trojan),
            "anytls" => Some(Protocol::AnyTls),
            "socks" | "socks5" => Some(Protocol::Socks),
            "http" | "https" => Some(Protocol::Http),
            "direct" => Some(Protocol::Direct),
            _ => None,
        }
    }

    /// Static protocol preference used when no explicit `preference:` list is
    /// configured. Lower rank wins when latencies are comparable. UDP/QUIC and
    /// Reality transports survive SNI-based blocking better than plain
    /// Shadowsocks/Trojan over TCP, which is why they lead.
    pub fn default_rank(self) -> u8 {
        match self {
            Protocol::Hysteria2 => 0,
            Protocol::VlessReality => 1,
            Protocol::Tuic => 2,
            Protocol::Vless => 3,
            Protocol::AnyTls => 4,
            Protocol::Trojan => 5,
            Protocol::Shadowsocks => 6,
            Protocol::WireGuard => 7,
            Protocol::Socks | Protocol::Http | Protocol::Direct | Protocol::Other => 9,
        }
    }
}

// ---------------------------------------------------------------------------
// Node tags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeTag {
    pub index: Option<u32>,
    pub geo: Option<String>,
    pub protocol: Protocol,
}

/// Tokenize a tag on `-` / `_`, left to right.
fn tag_tokens(input: &str) -> IResult<&str, Vec<&str>> {
    let sep = |c: char| c == '-' || c == '_';
    let (rest, first) = take_while1(|c: char| !sep(c)).parse(input)?;
    let (rest, tail) = fold_many0(
        preceded(take_while1(sep), take_while1(|c: char| !sep(c))),
        Vec::new,
        |mut acc: Vec<&str>, tok: &str| {
            acc.push(tok);
            acc
        },
    )
    .parse(rest)?;
    let mut tokens = Vec::with_capacity(tail.len() + 1);
    tokens.push(first);
    tokens.extend(tail);
    Ok((rest, tokens))
}

/// Parse a node tag into structured metadata. Never fails: an unrecognised tag
/// degrades to `Protocol::Other` with no index/geo instead of rejecting the
/// node (a selector must keep working with arbitrary user-chosen tags).
pub fn node_tag(input: &str) -> IResult<&str, NodeTag> {
    let (rest, tokens) = tag_tokens(input)?;
    let mut index = None;
    let mut geo = None;
    let mut protocol = Protocol::Other;
    let mut reality = false;

    for token in tokens {
        let lower = token.to_ascii_lowercase();
        if index.is_none() && !lower.is_empty() && lower.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = lower.parse::<u32>() {
                index = Some(n);
                continue;
            }
        }
        if let Some(proto) = Protocol::from_token(&lower) {
            if proto == Protocol::VlessReality {
                reality = true;
            }
            if protocol == Protocol::Other || protocol == Protocol::Vless {
                protocol = proto;
            }
            continue;
        }
        if geo.is_none()
            && lower.len() == 2
            && lower.bytes().all(|b| b.is_ascii_alphabetic())
            && lower != "ss"
        {
            geo = Some(lower);
        }
    }
    if reality {
        protocol = Protocol::VlessReality;
    }
    Ok((
        rest,
        NodeTag {
            index,
            geo,
            protocol,
        },
    ))
}

// ---------------------------------------------------------------------------
// URL / host:port
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Always starts with `/`.
    pub path: String,
}

impl Url {
    pub fn parse(input: &str) -> Result<Url, String> {
        let (rest, (scheme, authority, path)) =
            url_parts(input).map_err(|_| format!("invalid url: {input}"))?;
        if !rest.is_empty() {
            return Err(format!("invalid url: {input}"));
        }
        let (host, port) = split_authority(authority)?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            "socks5" | "socks5h" | "socks" => 1080,
            other => return Err(format!("unsupported scheme: {other}")),
        };
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        Ok(Url {
            scheme,
            host,
            port: port.unwrap_or(default_port),
            path,
        })
    }

    /// Reconstruct the full URL (used as the Clash API `delay` query value).
    pub fn to_url_string(&self) -> String {
        let default = if self.is_tls() { 443 } else { 80 };
        if self.port == default {
            format!("{}://{}{}", self.scheme, self.host, self.path)
        } else {
            format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
        }
    }

    pub fn is_tls(&self) -> bool {
        self.scheme == "https"
    }

    /// Authority used in the `Host:` header: no default port.
    pub fn host_header(&self) -> String {
        let default = if self.is_tls() { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn url_parts(input: &str) -> IResult<&str, (&str, &str, &str)> {
    let (rest, scheme) =
        take_while1(|c: char| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
            .parse(input)?;
    let (rest, _) = tag("://").parse(rest)?;
    let (rest, authority) = take_while1(|c: char| c != '/' && c != '?' && c != '#').parse(rest)?;
    let (rest, path) = take_while(|c: char| c != '?' && c != '#').parse(rest)?;
    Ok((rest, (scheme, authority, path)))
}

fn split_authority(authority: &str) -> Result<(String, Option<u16>), String> {
    // Strip userinfo (unsupported, but tolerate it rather than mis-parse).
    let host_port = match authority.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => authority,
    };
    if let Ok((rest, (host, port))) = host_port_parts(host_port) {
        if !rest.is_empty() {
            return Err(format!("invalid authority: {authority}"));
        }
        return Ok((host.to_string(), Some(port)));
    }
    Ok((host_port.to_string(), None))
}

fn host_port_parts(input: &str) -> IResult<&str, (&str, u16)> {
    let (rest, host) = take_while1(|c: char| c != ':').parse(input)?;
    let (rest, port) =
        preceded(tag(":"), map_res(digit1, |d: &str| d.parse::<u16>())).parse(rest)?;
    Ok((rest, (host, port)))
}

/// Parse `host:port` (or `[v6]:port`) — used for the SOCKS and API endpoints.
pub fn host_port(input: &str) -> Result<(String, u16), String> {
    let trimmed = input.trim();
    if let Some(inner) = trimmed.strip_prefix('[') {
        let (host, rest) = inner
            .split_once(']')
            .ok_or_else(|| format!("invalid host:port: {input}"))?;
        let port = rest
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| format!("invalid host:port: {input}"))?;
        return Ok((host.to_string(), port));
    }
    let (rest, (host, port)) =
        host_port_parts(trimmed).map_err(|_| format!("invalid host:port: {input}"))?;
    if !rest.is_empty() {
        return Err(format!("invalid host:port: {input}"));
    }
    Ok((host.to_string(), port))
}

// ---------------------------------------------------------------------------
// Cloudflare cdn-cgi/trace
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceInfo {
    pub ip: Option<String>,
    pub loc: Option<String>,
    pub warp: Option<String>,
    pub colo: Option<String>,
}

/// `ip=1.2.3.4\nloc=FR\nts=…\n` → typed info. Unknown keys are ignored so a
/// future Cloudflare field never breaks a probe.
pub fn trace_info(input: &str) -> IResult<&str, TraceInfo> {
    let (rest, pairs) = fold_many0(
        terminated(trace_kv, take_while(|c: char| c == '\n' || c == '\r')),
        Vec::new,
        |mut acc: Vec<(&str, &str)>, pair: (&str, &str)| {
            acc.push(pair);
            acc
        },
    )
    .parse(input)?;

    let mut info = TraceInfo::default();
    for (key, value) in pairs {
        let v = value.trim();
        if v.is_empty() {
            continue;
        }
        match key {
            "ip" => info.ip = Some(v.to_string()),
            "loc" => info.loc = Some(v.to_string()),
            "warp" => info.warp = Some(v.to_string()),
            "colo" => info.colo = Some(v.to_string()),
            _ => {}
        }
    }
    Ok((rest, info))
}

fn trace_kv(input: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(
        take_while1(|c: char| c != '=' && c != '\n' && c != '\r'),
        tag("="),
        take_while(|c: char| c != '\n' && c != '\r'),
    )
    .parse(input)
}

// ---------------------------------------------------------------------------
// HTTP/1.x response head
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    pairs: Vec<(String, String)>,
}

impl Headers {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn content_length(&self) -> Option<usize> {
        self.get("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    pub fn is_chunked(&self) -> bool {
        self.get("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

/// Index of the first byte after `\r\n\r\n`, i.e. where the body starts.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    find_subslice(buf, b"\r\n\r\n").map(|i| i + 4)
}

/// Find `needle` in `haystack` without regex/standard `contains` on slices.
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parse the response head (everything before the blank line).
pub fn parse_head(head: &[u8]) -> Result<(u16, Headers), String> {
    let (rest, (minor, code)) =
        http_status(head).map_err(|_| "malformed HTTP status line".to_string())?;
    let (rest, headers) = header_block(rest).map_err(|_| "malformed HTTP headers".to_string())?;
    if !rest.is_empty() && rest != b"\r\n" && rest != b"\n" {
        return Err("trailing bytes in HTTP head".to_string());
    }
    let _ = minor;
    Ok((code, headers))
}

fn http_status(input: &[u8]) -> IResult<&[u8], (u8, u16)> {
    let (rest, _) = tag(b"HTTP/1.".as_slice()).parse(input)?;
    let (rest, minor) = take_while_m_n(1, 1, |b: u8| b.is_ascii_digit()).parse(rest)?;
    let (rest, _) = tag(b" ".as_slice()).parse(rest)?;
    let (rest, code) = take_while_m_n(3, 3, |b: u8| b.is_ascii_digit()).parse(rest)?;
    let minor = minor[0] - b'0';
    let code = std::str::from_utf8(code)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Digit))
        })?;
    // RFC 9112: status-code is followed by SP before the reason phrase.
    let (rest, _) = tag(b" ".as_slice()).parse(rest)?;
    // Reason phrase ("OK", "No Content", …) is informational: skip it, then
    // consume the end of the status line.
    let (rest, _reason) = take_till(|b: u8| b == b'\r' || b == b'\n').parse(rest)?;
    let (rest, _) = tag(CRLF).parse(rest)?;
    Ok((rest, (minor, code)))
}

fn header_block(input: &[u8]) -> IResult<&[u8], Headers> {
    fold_many0(
        terminated(header_line, tag(CRLF)),
        Headers::default,
        |mut acc: Headers, line: (&[u8], &[u8])| {
            let name = String::from_utf8_lossy(line.0).trim().to_ascii_lowercase();
            let value = String::from_utf8_lossy(line.1).trim().to_string();
            if !name.is_empty() {
                acc.pairs.push((name, value));
            }
            acc
        },
    )
    .parse(input)
}

fn header_line(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    separated_pair(
        take_till(|b: u8| b == b':' || b == b'\r' || b == b'\n'),
        tag(b":".as_slice()),
        take_till(|b: u8| b == b'\r' || b == b'\n'),
    )
    .parse(input)
}

/// Decode a chunked body.
///
/// `Ok(None)` means "not complete yet, read more". On success returns the
/// decoded body together with the number of consumed framing bytes.
pub fn decode_chunked(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos >= buf.len() {
            return Ok(None);
        }
        let (rest, size) = match chunk_size(&buf[pos..]) {
            Ok(v) => v,
            Err(_) => return Ok(None), // incomplete size line
        };
        let consumed = buf.len() - pos - rest.len();
        pos += consumed;
        if size == 0 {
            // Trailer section: zero or more `name: value\r\n`, then a blank line.
            let tail = &buf[pos..];
            if tail.starts_with(b"\r\n") {
                return Ok(Some((out, pos + 2)));
            }
            return match find_subslice(tail, b"\r\n\r\n") {
                Some(idx) => Ok(Some((out, pos + idx + 4))),
                None => Ok(None), // trailers still arriving
            };
        }
        if buf.len() < pos + size + 2 {
            return Ok(None); // chunk body still arriving
        }
        out.extend_from_slice(&buf[pos..pos + size]);
        pos += size;
        if &buf[pos..pos + 2] != b"\r\n" {
            return Err("malformed chunk terminator".to_string());
        }
        pos += 2;
    }
}

fn chunk_size(input: &[u8]) -> IResult<&[u8], usize> {
    let (rest, hex) = take_while1(|b: u8| b.is_ascii_hexdigit()).parse(input)?;
    let (rest, _) = take_while(|b: u8| b == b';' || b == b' ' || b == b'\t').parse(rest)?;
    let (rest, _) = tag(CRLF).parse(rest)?;
    let size = std::str::from_utf8(hex)
        .ok()
        .and_then(|text| usize::from_str_radix(text, 16).ok())
        .ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Digit))
        })?;
    Ok((rest, size))
}

// ---------------------------------------------------------------------------
// .env files
// ---------------------------------------------------------------------------

/// `export KEY=value  # comment` → (`KEY`, `value`). Blank lines and comments
/// are filtered by the caller via [`skip_env_line`].
pub fn env_line(input: &str) -> IResult<&str, (String, String)> {
    let line = input.trim_end_matches(['\r', '\n']);
    let line = match line.strip_prefix("export ") {
        Some(rest) => rest.trim_start(),
        None => line,
    };
    let (rest, key) = take_while1(|c: char| c.is_ascii_alphanumeric() || c == '_').parse(line)?;
    let (rest, _) = tag("=").parse(rest)?;
    let mut value = rest.trim();
    if let Some(stripped) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        value = stripped;
    } else if let Some(stripped) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        value = stripped;
    } else if let Some(idx) = value.find(" #") {
        value = value[..idx].trim_end();
    }
    Ok(("", (key.to_string(), value.to_string())))
}

pub fn skip_env_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

// ---------------------------------------------------------------------------
// Percent-encoding (Clash API query strings)
// ---------------------------------------------------------------------------

/// RFC 3986 percent-encoding for query components/segments. Written out
/// explicitly rather than via a crate: one function, no dependency, no regex.
pub fn encode_component(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_structured_tag() {
        let (rest, tag) = node_tag("node-02-de-hysteria").unwrap();
        assert_eq!(rest, "");
        assert_eq!(tag.index, Some(2));
        assert_eq!(tag.geo.as_deref(), Some("de"));
        assert_eq!(tag.protocol, Protocol::Hysteria2);
    }

    #[test]
    fn parses_reality_tag() {
        let (_, tag) = node_tag("node-08-de-reality").unwrap();
        assert_eq!(tag.index, Some(8));
        assert_eq!(tag.protocol, Protocol::VlessReality);
    }

    #[test]
    fn parses_vless_tag() {
        let (_, tag) = node_tag("node-01-fr-vless").unwrap();
        assert_eq!(tag.index, Some(1));
        assert_eq!(tag.geo.as_deref(), Some("fr"));
        assert_eq!(tag.protocol, Protocol::Vless);
    }

    #[test]
    fn unknown_tags_degrade_gracefully() {
        let (_, tag) = node_tag("my custom outbound").unwrap();
        assert_eq!(tag.index, None);
        assert_eq!(tag.geo, None);
        assert_eq!(tag.protocol, Protocol::Other);
    }

    #[test]
    fn tag_with_underscore_separator() {
        let (_, tag) = node_tag("node_10_cz_vless").unwrap();
        assert_eq!(tag.index, Some(10));
        assert_eq!(tag.geo.as_deref(), Some("cz"));
        assert_eq!(tag.protocol, Protocol::Vless);
    }

    #[test]
    fn parses_https_url() {
        let url = Url::parse("https://api.openai.com/v1/models").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "api.openai.com");
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/v1/models");
        assert_eq!(url.host_header(), "api.openai.com");
    }

    #[test]
    fn parses_url_with_port_and_empty_path() {
        let url = Url::parse("http://127.0.0.1:9090").unwrap();
        assert_eq!(url.host, "127.0.0.1");
        assert_eq!(url.port, 9090);
        assert_eq!(url.path, "/");
        assert_eq!(url.host_header(), "127.0.0.1:9090");
    }

    #[test]
    fn rejects_bad_urls() {
        assert!(Url::parse("ftp://x/y").is_err());
        assert!(Url::parse("no-scheme").is_err());
    }

    #[test]
    fn parses_host_port_and_v6() {
        assert_eq!(
            host_port("127.0.0.1:10808").unwrap(),
            ("127.0.0.1".into(), 10808)
        );
        assert_eq!(host_port("[::1]:9090").unwrap(), ("::1".into(), 9090));
        assert!(host_port("127.0.0.1").is_err());
        assert!(host_port("127.0.0.1:99999").is_err());
    }

    #[test]
    fn parses_trace_payload() {
        let body = "fl=123abc\nh=1.1.1.1\nip=203.0.113.7\nts=1700000000.1\nvisit_scheme=https\nuag=x\ncolo=FRA\nsliver=none\nhttp=http/2\nloc=FR\ntls=TLSv1.3\nsni=off\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n";
        let (rest, info) = trace_info(body).unwrap();
        assert_eq!(rest, "");
        assert_eq!(info.ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(info.loc.as_deref(), Some("FR"));
        assert_eq!(info.warp.as_deref(), Some("off"));
        assert_eq!(info.colo.as_deref(), Some("FRA"));
    }

    #[test]
    fn parses_http_head() {
        let head =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n";
        let end = head_end(head).unwrap();
        let (code, headers) = parse_head(&head[..end - 2]).unwrap();
        assert_eq!(code, 200);
        assert_eq!(headers.get("content-type"), Some("application/json"));
        assert_eq!(headers.content_length(), Some(42));
        assert!(!headers.is_chunked());
    }

    #[test]
    fn rejects_garbage_status_line() {
        assert!(parse_head(b"GARBAGE\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 2000 OK\r\n\r\n").is_err());
    }

    #[test]
    fn decodes_chunked_body() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (decoded, consumed) = decode_chunked(body).unwrap().unwrap();
        assert_eq!(decoded, b"hello world");
        assert_eq!(consumed, body.len());
    }

    #[test]
    fn chunked_body_incomplete_returns_none() {
        assert!(decode_chunked(b"5\r\nhel").unwrap().is_none());
        assert!(decode_chunked(b"5\r\nhello\r\n0\r\n").unwrap().is_none());
    }

    #[test]
    fn chunked_rejects_bad_terminator() {
        assert!(decode_chunked(b"5\r\nhelloXX0\r\n\r\n").is_err());
    }

    #[test]
    fn parses_env_lines() {
        assert_eq!(
            env_line("export WATCHCAT_API_SECRET=\"s3cr3t\"\n")
                .unwrap()
                .1,
            ("WATCHCAT_API_SECRET".to_string(), "s3cr3t".to_string())
        );
        assert_eq!(
            env_line("API_URL=http://127.0.0.1:9090 # local\n")
                .unwrap()
                .1,
            ("API_URL".to_string(), "http://127.0.0.1:9090".to_string())
        );
        assert!(skip_env_line("# comment"));
        assert!(skip_env_line("   "));
    }

    #[test]
    fn encodes_query_components() {
        assert_eq!(
            encode_component("https://1.1.1.1/cdn-cgi/trace"),
            "https%3A%2F%2F1.1.1.1%2Fcdn-cgi%2Ftrace"
        );
        assert_eq!(
            encode_component("node-02-de-hysteria"),
            "node-02-de-hysteria"
        );
    }
}
