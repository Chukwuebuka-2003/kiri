//! `kiri udprelay`: published UDP ports from Windows reach the engine in
//! WSL2. WSL's localhost forwarding carries TCP only, so kiri-win binds the
//! UDP ports here, on Windows, and sends each datagram over wsl.exe's stdio
//! to this end, which sends it to the daemon's own UDP listener inside the
//! distro. Replies take the way back. Both ends share this file; the frames
//! are the proxy relay's (crates/kiri/src/hostrelay.rs).
//!
//!   kiri udprelay   (started by kiri-win, reads frames on stdin)

// Each build uses one end: the WSL end in Linux's kiri, the Windows end in
// kiri-win. The tests use both.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, BufReader, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

pub use crate::hostrelay::{read_frame, send, Out};
use serde_json::Value;

/// Windows → WSL: a datagram from client `id` starts here; data is the host
/// port (u16 BE). WSL opens one socket per client so replies stay separate.
pub const OPEN: u8 = 11;
/// Both ways: the datagram, keyed by the session id in the frame header.
pub const DATA: u8 = 12;
/// WSL → Windows: the daemon's reply to client `id`.
pub const REPLY: u8 = 13;
/// Either end: forget client `id`.
pub const CLOSE: u8 = 14;
/// Windows → WSL: relay this host port; data is `encode_target`.
pub const LISTEN: u8 = 15;
/// WSL → Windows: data is the host port (u16 BE) and a status byte.
pub const LISTENED: u8 = 16;
/// Windows → WSL: this host port is no longer published; data is u16 BE.
pub const UNLISTEN: u8 = 17;

const CHUNK: usize = 64 * 1024;
const IDLE: Duration = Duration::from_secs(60);
const MAX_SESSIONS: usize = 1024;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn port_of(data: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(0..2)?.try_into().ok()?))
}

/// Host port and the address the daemon listens on in the distro.
pub fn encode_target(port: u16, ip: IpAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    out.extend_from_slice(&port.to_be_bytes());
    match ip {
        IpAddr::V4(a) => {
            out.push(4);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(6);
            out.extend_from_slice(&a.octets());
        }
    }
    out
}

pub fn decode_target(data: &[u8]) -> Option<(u16, IpAddr)> {
    let port = port_of(data)?;
    match *data.get(2)? {
        4 if data.len() >= 7 => Some((port, IpAddr::V4(Ipv4Addr::new(data[3], data[4], data[5], data[6])))),
        6 if data.len() >= 19 => Some((port, IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[3..19]).ok()?)))),
        _ => None,
    }
}

/// The UDP bindings in Docker's container list (`GET /containers/json`):
/// host port and the daemon's address in the distro to send datagrams to.
/// A wildcard binding is reached on loopback, and the v4 and v6 sockets of
/// one `-p` are folded into one entry, preferring v4.
pub fn published_udp(containers: &Value) -> Vec<(u16, IpAddr)> {
    let mut out: Vec<(u16, IpAddr)> = Vec::new();
    for c in containers.as_array().into_iter().flatten() {
        for p in c["Ports"].as_array().into_iter().flatten() {
            if p["Type"].as_str() != Some("udp") {
                continue;
            }
            let Some(port) = p["PublicPort"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0) else { continue };
            let ip = match p["IP"].as_str().unwrap_or("") {
                "" | "0.0.0.0" => IpAddr::V4(Ipv4Addr::LOCALHOST),
                "::" => IpAddr::V6(Ipv6Addr::LOCALHOST),
                s => s.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            };
            match out.iter_mut().find(|(p, _)| *p == port) {
                Some(slot) if slot.1.is_ipv6() && ip.is_ipv4() => *slot = (port, ip),
                Some(_) => {}
                None => out.push((port, ip)),
            }
        }
    }
    out
}

/// A socket that can send to `target` inside this distro: its own loopback
/// when the daemon listens there, otherwise a wildcard source so Linux
/// picks an address that routes.
fn bind_for(target: IpAddr) -> io::Result<UdpSocket> {
    let sock = if target.is_loopback() {
        UdpSocket::bind(SocketAddr::new(target, 0))?
    } else if target.is_ipv4() {
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?
    } else {
        UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?
    };
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok(sock)
}

struct Session {
    sock: Arc<UdpSocket>,
    target: SocketAddr,
    last: Arc<Mutex<Instant>>,
    closed: Arc<AtomicBool>,
}

impl Session {
    /// Forgets the session and stops its reply reader.
    fn close(sessions: &Mutex<HashMap<u32, Session>>, id: u32) {
        if let Some(s) = lock(sessions).remove(&id) {
            s.closed.store(true, Ordering::SeqCst);
        }
    }
}

pub fn run() -> io::Result<()> {
    let out: Out = Arc::new(Mutex::new(io::stdout()));
    serve(io::stdin(), &out)
}

/// The WSL end: one socket per Windows client, so the daemon's reply to
/// that client comes back on a socket we can name in a REPLY frame.
pub fn serve(input: impl Read, out: &Out) -> io::Result<()> {
    let targets: Arc<Mutex<HashMap<u16, IpAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let sessions: Arc<Mutex<HashMap<u32, Session>>> = Arc::new(Mutex::new(HashMap::new()));
    let done = Arc::new(AtomicBool::new(false));
    {
        let (sessions, out, done) = (sessions.clone(), out.clone(), done.clone());
        std::thread::Builder::new()
            .name("kiri-udprelay-reap".into())
            .spawn(move || {
                let tick = Duration::from_millis(100);
                let mut waited = Duration::ZERO;
                while !done.load(Ordering::SeqCst) {
                    std::thread::sleep(tick);
                    waited += tick;
                    if waited < Duration::from_secs(10) {
                        continue;
                    }
                    waited = Duration::ZERO;
                    let idle: Vec<u32> = lock(&sessions)
                        .iter()
                        .filter(|(_, s)| lock(&s.last).elapsed() >= IDLE)
                        .map(|(id, _)| *id)
                        .collect();
                    for id in idle {
                        Session::close(&sessions, id);
                        let _ = send(&out, CLOSE, id, &[]);
                    }
                }
            })?;
    }
    let result = (|| {
        let mut r = BufReader::with_capacity(CHUNK, input);
        while let Some((kind, id, data)) = read_frame(&mut r)? {
            match kind {
                LISTEN => {
                    let Some((port, ip)) = decode_target(&data) else { continue };
                    lock(&targets).insert(port, ip);
                    let mut reply = port.to_be_bytes().to_vec();
                    reply.push(0);
                    send(out, LISTENED, 0, &reply)?;
                }
                UNLISTEN => {
                    let Some(port) = port_of(&data) else { continue };
                    lock(&targets).remove(&port);
                    let gone: Vec<u32> = lock(&sessions)
                        .iter()
                        .filter(|(_, s)| s.target.port() == port)
                        .map(|(id, _)| *id)
                        .collect();
                    for id in gone {
                        Session::close(&sessions, id);
                    }
                }
                OPEN => {
                    let Some(port) = port_of(&data) else { send(out, CLOSE, id, &[])?; continue };
                    let Some(ip) = lock(&targets).get(&port).copied() else { send(out, CLOSE, id, &[])?; continue };
                    if lock(&sessions).len() >= MAX_SESSIONS {
                        send(out, CLOSE, id, &[])?;
                        continue;
                    }
                    let Ok(sock) = bind_for(ip) else { send(out, CLOSE, id, &[])?; continue };
                    let sock = Arc::new(sock);
                    let last = Arc::new(Mutex::new(Instant::now()));
                    let closed = Arc::new(AtomicBool::new(false));
                    lock(&sessions).insert(id, Session { sock: sock.clone(), target: SocketAddr::new(ip, port), last: last.clone(), closed: closed.clone() });
                    let (out, reader_last) = (out.clone(), last.clone());
                    std::thread::Builder::new()
                        .name(format!("kiri-udprelay-{port}"))
                        .spawn(move || {
                            let mut buf = vec![0u8; CHUNK];
                            loop {
                                match sock.recv_from(&mut buf) {
                                    Ok((n, _)) => {
                                        *lock(&reader_last) = Instant::now();
                                        if send(&out, REPLY, id, &buf[..n]).is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                                        if closed.load(Ordering::SeqCst) {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            let _ = send(&out, CLOSE, id, &[]);
                        })?;
                }
                DATA => {
                    let session = lock(&sessions).get(&id).map(|s| (s.sock.clone(), s.target, s.last.clone()));
                    match session {
                        Some((sock, target, last)) => {
                            let _ = sock.send_to(&data, target);
                            *lock(&last) = Instant::now();
                        }
                        None => send(out, CLOSE, id, &[])?,
                    }
                }
                CLOSE => Session::close(&sessions, id),
                _ => {}
            }
        }
        Ok(())
    })();
    done.store(true, Ordering::SeqCst);
    result
}

/// A Windows client, as the Windows end knows it.
#[derive(Clone)]
pub struct Client {
    pub sock: Arc<UdpSocket>,
    pub peer: SocketAddr,
    pub port: u16,
    pub last: Arc<Mutex<Instant>>,
}

pub type Clients = Arc<Mutex<HashMap<u32, Client>>>;

/// The Windows end's frame reader: replies go back to the client datagram
/// that asked for them. It runs on the wsl.exe stdout thread.
pub fn dial_side(input: impl Read, clients: &Clients) -> io::Result<()> {
    let mut r = BufReader::with_capacity(CHUNK, input);
    while let Some((kind, id, data)) = read_frame(&mut r)? {
        match kind {
            REPLY => {
                let client = lock(clients).get(&id).cloned();
                if let Some(c) = client {
                    let _ = c.sock.send_to(&data, c.peer);
                    *lock(&c.last) = Instant::now();
                }
            }
            CLOSE => {
                lock(clients).remove(&id);
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::net::UnixStream;

    #[test]
    fn bindings_from_the_container_list() {
        let list = json!([{"Ports": [
            {"IP": "0.0.0.0", "PublicPort": 1812, "PrivatePort": 1812, "Type": "udp"},
            {"IP": "::", "PublicPort": 1812, "PrivatePort": 1812, "Type": "udp"},
            {"IP": "127.0.0.1", "PublicPort": 1813, "PrivatePort": 1813, "Type": "udp"},
            {"IP": "0.0.0.0", "PublicPort": 1814, "PrivatePort": 1814, "Type": "tcp"},
            {"IP": "0.0.0.0", "PublicPort": 0, "PrivatePort": 1815, "Type": "udp"},
        ]}]);
        assert_eq!(
            published_udp(&list),
            vec![(1812, IpAddr::V4(Ipv4Addr::LOCALHOST)), (1813, IpAddr::V4(Ipv4Addr::LOCALHOST))]
        );
        for (port, ip) in [(42, IpAddr::V4(Ipv4Addr::LOCALHOST)), (65535, IpAddr::V6(Ipv6Addr::LOCALHOST))] {
            assert_eq!(decode_target(&encode_target(port, ip)), Some((port, ip)));
        }
        assert_eq!(decode_target(&[0, 42, 9, 1, 2, 3, 4]), None);
    }

    /// Both ends over a pair of pipes, as wsl.exe's stdio carries them: a
    /// "daemon" echoing UDP on this machine's loopback, as the engine does
    /// inside WSL, reached with the frames kiri-win would send.
    #[test]
    fn datagrams_reach_the_daemon_and_the_reply_gets_back() {
        let daemon = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let target = daemon.local_addr().unwrap().port();
        let echo = daemon.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; CHUNK];
            while let Ok((n, peer)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], peer);
            }
        });

        let (wsl, win) = UnixStream::pair().unwrap();
        let wsl_out: Out = Arc::new(Mutex::new(wsl.try_clone().unwrap()));
        let win_out: Out = Arc::new(Mutex::new(win.try_clone().unwrap()));
        std::thread::spawn(move || {
            let _ = serve(wsl, &wsl_out);
        });
        let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
        let reader_clients = clients.clone();
        std::thread::spawn(move || {
            let _ = dial_side(win, &reader_clients);
        });

        send(&win_out, LISTEN, 0, &encode_target(target, IpAddr::V4(Ipv4Addr::LOCALHOST))).unwrap();
        let client = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer = client.local_addr().unwrap();
        let wind = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).unwrap());
        let new_client = |_id: u32| Client { sock: wind.clone(), peer, port: target, last: Arc::new(Mutex::new(Instant::now())) };
        for (id, body) in [(1u32, &b"radius one"[..]), (2, &b"radius two"[..])] {
            clients.lock().unwrap().insert(id, new_client(id));
            send(&win_out, OPEN, id, &target.to_be_bytes()).unwrap();
            send(&win_out, DATA, id, body).unwrap();
            let mut got = vec![0u8; 64];
            let (n, _) = client.recv_from(&mut got).unwrap();
            assert_eq!(&got[..n], body);
        }

        send(&win_out, CLOSE, 1, &[]).unwrap();
        send(&win_out, DATA, 1, b"forgotten").unwrap();
        send(&win_out, DATA, 2, b"still here").unwrap();
        let mut got = vec![0u8; 64];
        let (n, _) = client.recv_from(&mut got).unwrap();
        assert_eq!(&got[..n], b"still here");

        send(&win_out, UNLISTEN, 0, &target.to_be_bytes()).unwrap();
        clients.lock().unwrap().insert(3, new_client(3));
        send(&win_out, OPEN, 3, &target.to_be_bytes()).unwrap();
        send(&win_out, DATA, 3, b"nope").unwrap();
        client.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        assert!(client.recv_from(&mut [0u8; 64]).is_err());
    }
}
