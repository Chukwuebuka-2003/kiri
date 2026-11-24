//! The daemon's BuildKit: buildx's `docker` driver speaks gRPC straight at
//! this socket, and a stream into the guest's buildkitd carries every byte.
//!
//! buildx dials the engine socket with HTTP/2 cleartext (prior knowledge:
//! exactly how grpc-go behaves against Docker Desktop on a unix socket) and
//! runs both the BuildKit control API and its session services over that one
//! connection — auth, ssh, local contexts and all. h2 is a framed byte
//! protocol, so the relay does not need to understand it: copying the bytes
//! both ways keeps HEADERS, DATA, trailers, flow-control windows, PINGs and
//! stream IDs exactly as buildx and buildkitd wrote them. Terminating h2 on
//! each side and re-encoding gRPC messages twice only introduces state-machine
//! errors (#89 review), so this module is a plain tunnel.
//!
//! buildkitd starts on demand in the guest; the first dial may ride over the
//! exchange that boots it, which is why `dial` retries the connect.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::io::unix::AsyncFd;

use super::builder;
use super::engine::Engine;
use crate::diag;

/// Who is on a BuildKit connection now, and when someone last was (Unix
/// seconds; 0 = nobody has yet). `builder::idle_secs()` of quiet with nobody
/// connected, and the guest's buildkitd is stopped again.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static LAST_USE: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The tokio island: the relays are the one thing in the daemon that wants
/// real concurrency, so they borrow two threads that everyone else agrees
/// never to touch.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("kiri-grpc")
            // The tunnel uses AsyncFd and tokio::time::sleep: without the I/O
            // and time drivers every session would panic on its first read.
            .enable_all()
            .build()
            .expect("cannot start the BuildKit runtime")
    })
}

/// A buildx connection arrives here from the socket accept loop when the
/// connection opens with h2's preface. One thread per connection, as the
/// engine is thread-based: the vsock dial may boot the whole VM first, so
/// this thread blocks politely until what follows wants tokio. Runs until
/// buildx goes (or its VM does), then falls off the end.
pub fn serve(conn: UnixStream, engine: Arc<Engine>) {
    let outcome: io::Result<()> = runtime().block_on(async move {
        let guest = dial(&engine).await?;
        tunnel(OwnedFd::from(conn), guest.fd.try_clone()?).await
    });
    if let Err(e) = outcome {
        // buildx walking away mid-build, the VM going to sleep: all
        // ordinary, so this is a line, not an error report.
        diag::info!("a BuildKit connection ended", error = e.to_string());
    }
}

/// Lowers the active count on every exit, including the early error returns.
struct ActiveGuard;

impl ActiveGuard {
    fn new() -> Self {
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection into the guest's BuildKit relay, with patience. The guest
/// accepts vsock connections before buildkitd is listening, so a successful
/// connect is not the cue that it is ready — but buildkitd's unix socket is
/// only created once it is up, so a connect that reaches the guest and is
/// relayed on is enough. `BuildkitStart` is sent first; `ensure` is idempotent.
async fn dial(engine: &Engine) -> io::Result<kiri_vmm::VsockStream> {
    let config = builder::guest_config(engine);
    let layers = builder::guest_layers(engine, &mut |_| {}).map_err(|e| io::Error::other(format!("cannot list the BuildKit image layers: {e:?}")))?;
    engine.buildkit_start(&layers, &config).map_err(|e| io::Error::other(format!("cannot start buildkitd: {e:?}")))?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match engine.buildkit_connect() {
            Ok(stream) => return Ok(stream),
            Err(e) => diag::debug!("the BuildKit dial failed", error = format!("{e:?}")),
        }
        if Instant::now() > deadline {
            return Err(io::Error::other("the guest never answered the BuildKit dial"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Copy both directions at once until both end. buildx and buildkitd each
/// have their own h2 connection; the bytes between them are opaque to us.
async fn tunnel(buildx_fd: OwnedFd, guest_fd: OwnedFd) -> io::Result<()> {
    let _active = ActiveGuard::new();
    LAST_USE.store(now_secs(), Ordering::Relaxed);

    let (mut from_buildx, mut to_buildx) = tokio::io::split(RawFdStream::new(buildx_fd)?);
    let (mut from_guest, mut to_guest) = tokio::io::split(RawFdStream::new(guest_fd)?);
    let up = tokio::spawn(async move { copy(&mut from_buildx, &mut to_guest).await });
    let down = tokio::spawn(async move { copy(&mut from_guest, &mut to_buildx).await });
    let up = up.await.map_err(join_error)?;
    let down = down.await.map_err(join_error)?;
    diag::info!("BuildKit tunnel ended", up = format!("{up:?}"), down = format!("{down:?}"));
    up?;
    down?;
    Ok(())
}

fn join_error(e: tokio::task::JoinError) -> io::Error {
    io::Error::other(e.to_string())
}

async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(from: &mut R, to: &mut W) -> io::Result<u64> {
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        LAST_USE.store(now_secs(), Ordering::Relaxed);
        to.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

fn set_nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_raw(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn write_raw(fd: i32, buf: &[u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// A socket fd as an async stream. The readiness guard is kept after a
/// successful read so a second read can drain what is still buffered; it is
/// cleared only once the fd would block.
struct RawFdStream {
    fd: AsyncFd<OwnedFd>,
}

impl RawFdStream {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(fd.as_raw_fd())?;
        // SAFETY: `fd` is owned by us.
        #[allow(deprecated)]
        Ok(Self { fd: AsyncFd::new(fd)? })
    }
}

impl AsyncRead for RawFdStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let ready = match this.fd.poll_read_ready(cx) {
            Poll::Ready(Ok(g)) => g,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let unfilled = buf.initialize_unfilled();
        // Clear the guard on every outcome: an EOF that arrived with the last
        // chunk must wake the next read, not sit behind a stale readiness.
        let mut ready = ready;
        ready.clear_ready();
        match read_raw(this.fd.as_raw_fd(), unfilled) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for RawFdStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let ready = match this.fd.poll_write_ready(cx) {
            Poll::Ready(Ok(g)) => g,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let mut ready = ready;
        ready.clear_ready();
        match write_raw(this.fd.as_raw_fd(), buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// There is no half-close on a vsock/Unix stream; EOF on the other
    /// direction ends the tunnel.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Never `builder::idle_secs()` without a BuildKit connection, and the
/// guest's buildkitd keeps running; quiet for that long, and it stops.
pub fn watch(engine: Arc<Engine>) {
    let spawned = std::thread::Builder::new().name("kiri-buildkit-idle".into()).spawn(move || loop {
        std::thread::sleep(Duration::from_secs(15));
        if ACTIVE.load(Ordering::Relaxed) != 0 {
            continue;
        }
        let last = LAST_USE.load(Ordering::Relaxed);
        if last == 0 || now_secs() < last + builder::idle_secs() {
            continue;
        }
        LAST_USE.store(0, Ordering::Relaxed);
        let _ = engine.buildkit_stop();
    });
    if let Err(e) = spawned {
        diag::warn!("cannot start the BuildKit idle watcher", error = e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon's relay runtime needs both drivers: `dial` sleeps and the
    /// tunnel wraps sockets in `AsyncFd`.
    #[test]
    fn the_relay_runtime_has_io_and_time_drivers() {
        super::runtime().block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            let (socket, _peer) = tokio::net::UnixStream::pair().unwrap();
            #[allow(deprecated)]
            tokio::io::unix::AsyncFd::new(socket).unwrap();
        });
    }

    /// A fake buildkitd that echoes chunks before the request ends: BuildKit's
    /// session and status RPCs are two-way streams that stay open for a build.
    #[test]
    fn tunnel_copies_bytes_both_ways() {
        super::runtime().block_on(async {
            let (buildx, buildx_peer) = UnixStream::pair().unwrap();
            let (guest, guest_peer) = UnixStream::pair().unwrap();
            set_nonblocking(buildx_peer.as_raw_fd()).unwrap();
            set_nonblocking(guest_peer.as_raw_fd()).unwrap();
            let buildx_peer = tokio::net::UnixStream::from_std(buildx_peer).unwrap();
            let guest_peer = tokio::net::UnixStream::from_std(guest_peer).unwrap();

            let fake = tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(guest_peer);
                // Read exactly the two chunks, echo each, then close: a real
                // buildkitd keeps the stream open for a whole build, but a
                // test twin must end so the tunnel can finish.
                let mut seen = vec![0u8; 8];
                r.read_exact(&mut seen).await.unwrap();
                w.write_all(b"echo:pingecho:pong").await.unwrap();
                seen
            });

            let client = tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(buildx_peer);
                w.write_all(b"ping").await.unwrap();
                w.write_all(b"pong").await.unwrap();
                let mut got = [0u8; 18];
                r.read_exact(&mut got).await.unwrap();
                got.to_vec()
            });

            tunnel(OwnedFd::from(buildx), OwnedFd::from(guest)).await.unwrap();
            assert_eq!(fake.await.unwrap(), b"pingpong");
            assert_eq!(client.await.unwrap(), b"echo:pingecho:pong");
        });
    }
}
