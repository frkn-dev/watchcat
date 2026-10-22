//! `mock-clash` — a fake sing-box Clash API plus a fake SOCKS5 inbound.
//!
//! Purpose: exercise the whole watchdog against a deterministic target, with no
//! sing-box, no real nodes and no network — for CI, for `docs/OPERATIONS.md`
//! demos, and for the failover integration test.
//!
//! Implemented surface (exactly what watchcat uses):
//!
//! ```text
//! GET  /version
//! GET  /proxies/{selector}                 -> {"type":"Selector","now":…,"all":[…]}
//! GET  /proxies/{tag}/delay?url=&timeout=  -> {"delay":N} | 504 {"message":"…"}
//! PUT  /proxies/{selector}                 -> 204, switches `now`
//! ```
//!
//! Plus an optional SOCKS5 listener that answers any tunnelled HTTP request with
//! `200` + a Cloudflare-like `cdn-cgi/trace` body, so the end-to-end probe has
//! something real to talk to. `--block <tag>` makes that listener answer `403`
//! while the blocked tag is active (stand-in for a geo-blocked exit).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NODES: [&str; 10] = [
    "node-01-fr-vless",
    "node-02-de-hysteria",
    "node-03-nl-shadowsocks",
    "node-04-fi-tuic",
    "node-05-se-vless",
    "node-06-pl-hysteria",
    "node-07-ee-wireguard",
    "node-08-de-reality",
    "node-09-fr-hysteria",
    "node-10-cz-vless",
];

struct Config {
    api_addr: String,
    socks_addr: Option<String>,
    selector: String,
    secret: Option<String>,
    fail: Option<String>,
    /// Node starts failing after this many delay probes (0 = immediately).
    fail_after: u32,
    slow: Option<(String, u32)>,
    block: Option<String>,
    nodes: Vec<String>,
}

struct State {
    now: String,
    probes: HashMap<String, u32>,
    switches: u32,
}

fn main() {
    let mut config = Config {
        api_addr: "127.0.0.1:19090".to_string(),
        socks_addr: Some("127.0.0.1:19080".to_string()),
        selector: "main-outbound".to_string(),
        secret: None,
        fail: None,
        fail_after: 0,
        slow: None,
        block: None,
        nodes: NODES.iter().map(|s| s.to_string()).collect(),
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut take = |name: &str| -> String {
            args.next()
                .unwrap_or_else(|| panic!("{name} requires a value"))
        };
        match arg.as_str() {
            "--api" => config.api_addr = take("--api"),
            "--socks" => config.socks_addr = Some(take("--socks")),
            "--no-socks" => config.socks_addr = None,
            "--selector" => config.selector = take("--selector"),
            "--secret" => config.secret = Some(take("--secret")),
            "--fail" => config.fail = Some(take("--fail")),
            "--fail-after" => {
                config.fail_after = take("--fail-after").parse().expect("--fail-after: u32")
            }
            "--block" => config.block = Some(take("--block")),
            "--slow" => {
                let spec = take("--slow");
                let (tag, ms) = spec.rsplit_once(':').expect("--slow TAG:MS");
                config.slow = Some((tag.to_string(), ms.parse().expect("ms")));
            }
            "--nodes" => {
                let n: usize = take("--nodes").parse().expect("--nodes: usize");
                config.nodes = NODES
                    .iter()
                    .take(n.min(NODES.len()))
                    .map(|s| s.to_string())
                    .collect();
            }
            "-h" | "--help" => {
                println!(
                    "mock-clash [--api ADDR] [--socks ADDR|--no-socks] [--selector TAG]\n\
                     \x20          [--secret S] [--fail TAG] [--fail-after N] [--slow TAG:MS]\n\
                     \x20          [--block TAG] [--nodes N]"
                );
                return;
            }
            other => panic!("unknown argument: {other}"),
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    runtime.block_on(async move {
        let state = Arc::new(Mutex::new(State {
            now: config.nodes[0].clone(),
            probes: HashMap::new(),
            switches: 0,
        }));

        let api_listener = TcpListener::bind(&config.api_addr).await.expect("bind api");
        let api_addr = api_listener.local_addr().unwrap();
        println!("MOCK_READY api=http://{api_addr}");

        let socks_listener = match &config.socks_addr {
            Some(addr) => {
                let listener = TcpListener::bind(addr).await.expect("bind socks");
                let addr = listener.local_addr().unwrap();
                println!("MOCK_READY socks=socks5://{addr}");
                Some(listener)
            }
            None => None,
        };

        let config = Arc::new(config);
        if let Some(listener) = socks_listener {
            let state = state.clone();
            let config = config.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        break;
                    };
                    let state = state.clone();
                    let config = config.clone();
                    tokio::spawn(async move {
                        let _ = serve_socks(socket, state, config).await;
                    });
                }
            });
        }

        loop {
            let Ok((socket, _)) = api_listener.accept().await else {
                break;
            };
            let state = state.clone();
            let config = config.clone();
            tokio::spawn(async move {
                let _ = serve_api(socket, state, config).await;
            });
        }
    });
}

fn node_latency(index: usize) -> u32 {
    20 + (index as u32 % 10) * 5
}

fn json_response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn serve_api(mut socket: TcpStream, state: Arc<Mutex<State>>, config: Arc<Config>) {
    let mut buf = vec![0u8; 8192];
    let mut read = 0usize;
    loop {
        match socket.read(&mut buf[read..]).await {
            Ok(0) => return,
            Ok(n) => {
                read += n;
                if find(&buf[..read], b"\r\n\r\n").is_some() {
                    break;
                }
                if read == buf.len() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let head = String::from_utf8_lossy(&buf[..read]).to_string();
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default().to_string();

    if let Some(secret) = &config.secret {
        let expected = format!("authorization: bearer {secret}");
        if !head.to_ascii_lowercase().contains(&expected) {
            let _ = socket
                .write_all(&json_response(401, "{\"message\":\"unauthorized\"}"))
                .await;
            return;
        }
    }

    let response = route(method, &path, &head, &state, &config);
    let _ = socket.write_all(&response).await;
    let _ = socket.shutdown().await;
}

fn route(
    method: &str,
    path: &str,
    head: &str,
    state: &Arc<Mutex<State>>,
    config: &Config,
) -> Vec<u8> {
    let selector_path = format!("/proxies/{}", config.selector);
    if method == "GET" && path == "/version" {
        return json_response(200, "{\"version\":\"mock-1.0.0\"}");
    }

    if method == "GET" && path == selector_path {
        let state = state.lock().unwrap();
        let body = json!({
            "type": "Selector",
            "now": state.now,
            "all": config.nodes,
        });
        return json_response(200, &body.to_string());
    }

    if method == "PUT" && path == selector_path {
        let name = parse_name(head);
        let mut state = state.lock().unwrap();
        let Some(name) = name else {
            return json_response(400, "{\"message\":\"missing name\"}");
        };
        if !config.nodes.contains(&name) {
            return json_response(400, "{\"message\":\"not a member\"}");
        }
        let from = state.now.clone();
        state.now = name.clone();
        state.switches += 1;
        println!(
            "MOCK_SWITCH {} -> {} (total {})",
            from, name, state.switches
        );
        return "HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            .as_bytes()
            .to_vec();
    }

    if method == "GET" && path.starts_with("/proxies/") && path.contains("/delay?") {
        let raw_tag = path
            .trim_start_matches("/proxies/")
            .split("/delay?")
            .next()
            .unwrap_or_default()
            .to_string();
        let tag = percent_decode(&raw_tag);
        let mut state = state.lock().unwrap();
        let counter = state.probes.entry(tag.clone()).or_insert(0);
        *counter += 1;
        let count = *counter;

        let index = config
            .nodes
            .iter()
            .position(|node| *node == tag)
            .unwrap_or(0);
        let mut latency = node_latency(index);
        if let Some((slow_tag, slow_ms)) = &config.slow {
            if *slow_tag == tag {
                latency = *slow_ms;
            }
        }

        let failing = config.fail.as_deref() == Some(tag.as_str()) && count > config.fail_after;
        if failing {
            return json_response(504, "{\"message\":\"context deadline exceeded\"}");
        }
        return json_response(200, &format!("{{\"delay\":{latency}}}"));
    }

    json_response(404, "{\"message\":\"not found\"}")
}

/// Extract `{"name":"…"}` from the request body (after the blank line).
fn parse_name(head: &str) -> Option<String> {
    let body = head.split("\r\n\r\n").nth(1)?;
    let key = body.find("\"name\"")?;
    let rest = &body[key + 6..];
    let start = rest.find('"')? + 1;
    let rest = &rest[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

async fn serve_socks(
    mut socket: TcpStream,
    state: Arc<Mutex<State>>,
    config: Arc<Config>,
) -> std::io::Result<()> {
    let mut greeting = [0u8; 3];
    socket.read_exact(&mut greeting).await?;
    socket.write_all(&[0x05, 0x00]).await?;

    let mut head = [0u8; 4];
    socket.read_exact(&mut head).await?;
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            socket.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            socket.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            socket.read_exact(&mut rest).await?;
        }
        _ => return Ok(()),
    }
    socket
        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
        .await?;

    let mut request = vec![0u8; 4096];
    let n = socket.read(&mut request).await?;
    let request_line = String::from_utf8_lossy(&request[..n])
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();

    let (blocked, exit_loc) = {
        let state = state.lock().unwrap();
        let blocked = config
            .block
            .as_deref()
            .map(|tag| tag == state.now)
            .unwrap_or(false);
        // Derive a stable fake exit country from the active tag.
        let loc = if state.now.contains("-de-") {
            "DE"
        } else if state.now.contains("-nl-") {
            "NL"
        } else if state.now.contains("-cz-") {
            "CZ"
        } else {
            "FR"
        };
        (blocked, loc)
    };

    let (status, body) = if blocked {
        ("403 Forbidden", "blocked by mock".to_string())
    } else {
        (
            "200 OK",
            format!("fl=1\nh=1.1.1.1\nip=203.0.113.7\nts=0\nvisit_scheme=https\ncolo=MSK\nloc={exit_loc}\nwarp=off\n"),
        )
    };

    println!("MOCK_E2E {request_line} -> {status}");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.shutdown().await;
    Ok(())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' && idx + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[idx + 1..idx + 3]).unwrap_or("");
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value);
                idx += 3;
                continue;
            }
        }
        out.push(bytes[idx]);
        idx += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
