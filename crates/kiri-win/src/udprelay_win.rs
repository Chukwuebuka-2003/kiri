//! Windows' end of the published UDP port relay (crates/kiri/src/udprelay.rs):
//! WSL's localhost forwarding carries TCP only, so a UDP port published by
//! an engine in WSL cannot be reached from Windows. kiri-win binds the port
//! here and sends each datagram over wsl.exe's stdio to `kiri udprelay`.

use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::windows::process::CommandExt;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::udprelay_proto as proto;

const IDLE: Duration = Duration::from_secs(60);

struct Relay {
    out: proto::Out,
    distro: Option<String>,
    clients: proto::Clients,
    listeners: Mutex<HashMap<u16, Arc<UdpSocket>>>,
    next: AtomicU32,
    dead: AtomicBool,
}

static RELAY: Mutex<Option<Arc<Relay>>> = Mutex::new(None);
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn log_once(msg: String) {
    let mut last = lock(&LAST_ERROR);
    if *last != msg {
        crate::serve::log(&msg);
        *last = msg;
    }
}

fn start(distro: Option<String>) -> io::Result<Arc<Relay>> {
    let mut cmd = crate::win::tool("wsl.exe");
    if let Some(d) = &distro {
        cmd.args(["-d", d]);
    }
    let mut child = cmd
        .args(["-u", "root", "--", "/usr/local/bin/kiri", "udprelay"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000)
        .spawn()?;
    let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else { return Err(io::Error::other("wsl.exe has no stdio")) };
    let relay = Arc::new(Relay {
        out: Arc::new(Mutex::new(input)),
        distro,
        clients: Arc::new(Mutex::new(HashMap::new())),
        listeners: Mutex::new(HashMap::new()),
        next: AtomicU32::new(1),
        dead: AtomicBool::new(false),
    });
    let r = relay.clone();
    std::thread::Builder::new().name("kiri-udprelay".into()).spawn(move || {
        let end = proto::dial_side(output, &r.clients);
        r.dead.store(true, Ordering::SeqCst);
        // Let go of the Windows ports: a new relay binds them again.
        lock(&r.listeners).clear();
        lock(&r.clients).clear();
        let status = child.wait();
        log_once(format!("UDP port relay ended: {end:?}, {status:?}"));
    })?;
    Ok(relay)
}

fn relay(distro: String) -> Option<Arc<Relay>> {
    let mut slot = lock(&RELAY);
    match slot.as_ref() {
        Some(r) if !r.dead.load(Ordering::SeqCst) && r.distro.as_deref() == Some(distro.as_str()) => Some(r.clone()),
        _ => match start(Some(distro.clone())) {
            Ok(r) => {
                *slot = Some(r.clone());
                Some(r)
            }
            Err(e) => {
                log_once(format!("UDP port relay: {e}"));
                None
            }
        },
    }
}

/// Brings the Windows listeners in line with the engine's UDP bindings.
/// Called on every container list refresh: starts, stops and restarts of
/// Kiri or the engine all come through here.
pub fn sync(containers: &serde_json::Value) {
    let wanted = proto::published_udp(containers);
    let desired: HashSet<u16> = wanted.iter().map(|(port, _)| *port).collect();
    // With nothing published there is nothing to start WSL for; an old
    // listener would only be there if a previous sync had ports to drop.
    if desired.is_empty() && lock(&RELAY).as_ref().is_none() {
        return;
    }
    let Some(distro) = crate::engine::distro().or_else(crate::setup::distro) else { return };
    let Some(r) = relay(distro) else { return };
    let mut listeners = lock(&r.listeners);

    let stale: Vec<u16> = listeners.keys().copied().filter(|port| !desired.contains(port)).collect();
    for port in stale {
        listeners.remove(&port);
        let _ = proto::send(&r.out, proto::UNLISTEN, 0, &port.to_be_bytes());
        let gone: Vec<u32> = lock(&r.clients).iter().filter(|(_, c)| c.port == port).map(|(id, _)| *id).collect();
        for id in gone {
            lock(&r.clients).remove(&id);
        }
    }

    for (port, ip) in wanted {
        if listeners.contains_key(&port) {
            continue;
        }
        // A wildcard binding is reached on loopback: bind every interface
        // here, as Docker does. An explicit host address binds just that one.
        let bind = if ip.is_loopback() {
            if ip.is_ipv4() { SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)) } else { SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)) }
        } else {
            SocketAddr::new(ip, port)
        };
        let sock = match UdpSocket::bind(bind) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log_once(format!("UDP port {port}: {e}"));
                continue;
            }
        };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
        // Frames share one stream, so this LISTEN is read before any OPEN
        // the listener below sends.
        let _ = proto::send(&r.out, proto::LISTEN, 0, &proto::encode_target(port, ip));
        let (r2, s2) = (r.clone(), sock.clone());
        if let Err(e) = std::thread::Builder::new().name(format!("kiri-udp-{port}")).spawn(move || listen_port(r2, port, s2)) {
            log_once(format!("UDP port {port} listener: {e}"));
            continue;
        }
        listeners.insert(port, sock);
    }
}

/// One Windows socket: every datagram gets a session id, once per client,
/// so the WSL end can send the answer back to this exact client.
fn listen_port(r: Arc<Relay>, port: u16, sock: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let (id, fresh, last) = {
                    let mut clients = lock(&r.clients);
                    if let Some((&id, c)) = clients.iter().find(|(_, c)| c.port == port && c.peer == peer) {
                        (id, false, c.last.clone())
                    } else {
                        let id = r.next.fetch_add(1, Ordering::SeqCst);
                        let last = Arc::new(Mutex::new(Instant::now()));
                        clients.insert(id, proto::Client { sock: sock.clone(), peer, port, last: last.clone() });
                        (id, true, last)
                    }
                };
                *lock(&last) = Instant::now();
                if fresh {
                    let _ = proto::send(&r.out, proto::OPEN, id, &port.to_be_bytes());
                }
                let _ = proto::send(&r.out, proto::DATA, id, &buf[..n]);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                let idle: Vec<u32> = lock(&r.clients)
                    .iter()
                    .filter(|(_, c)| c.port == port && lock(&c.last).elapsed() >= IDLE)
                    .map(|(id, _)| *id)
                    .collect();
                for id in idle {
                    let _ = proto::send(&r.out, proto::CLOSE, id, &[]);
                    lock(&r.clients).remove(&id);
                }
                if r.dead.load(Ordering::SeqCst) {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}
