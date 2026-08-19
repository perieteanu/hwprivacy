//! Unix-socket server: the root helper's only interface to the outside.
//!
//! # Threading
//!
//! BPF map handles stay on the main thread and are never shared. A connection
//! gets two threads — a reader that turns lines into [`Request`]s and a writer
//! that pumps [`Reply`]s out — and they talk to the main loop over channels.
//! Requests are answered by the main thread, which is the only thing that
//! touches the kernel.
//!
//! ```text
//!   reader thread  --req_tx-->  MAIN LOOP (owns the maps)
//!   writer thread  <--rep_tx--  MAIN LOOP
//! ```
//!
//! # One client at a time
//!
//! Deliberate for now. There is exactly one intended client — the user's
//! `hwprivacy-daemon` — and a second connection would raise "whose policy
//! wins?", which is a real question with no obvious answer. A new connection
//! displaces the old one rather than racing it.
//!
//! # Access control
//!
//! The socket's mode and group ARE the access control; the protocol grants
//! nothing on its own. Anyone who can open the socket can set camera policy,
//! so the directory is 0755 and the socket 0660, group-owned by the user who
//! runs the daemon.

use anyhow::{Context, Result};
use hwprivacy_proto::{encode_line, Reply, Request, PROTO_VERSION};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};

/// A request from a client, paired with the channel its answer goes back on.
pub type Incoming = (Request, Sender<Reply>);

pub struct SocketServer {
    pub path: PathBuf,
    /// Requests arriving from the connected client.
    pub requests: Receiver<Incoming>,
    /// Events to push to the connected client. Sends fail silently when
    /// nobody is connected — that is normal, not an error.
    pub events: Sender<Reply>,
}

/// Bind the socket and start accepting.
///
/// `group` is the group name to own the socket, so an unprivileged daemon can
/// connect. Failure to resolve it is fatal: silently falling back to root-only
/// would leave the daemon unable to connect with no explanation.
pub fn serve(path: &Path, group: &str) -> Result<SocketServer> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }

    // A leftover socket from a killed process would make bind() fail with
    // EADDRINUSE. Nothing else owns this path.
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("cannot remove stale socket {}", path.display()))?;
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("cannot bind {}", path.display()))?;

    let gid = lookup_gid(group)
        .with_context(|| format!("cannot resolve group '{group}'"))?;
    chown_group(path, gid)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;

    let (req_tx, req_rx) = std::sync::mpsc::channel::<Incoming>();
    let (evt_tx, evt_rx) = std::sync::mpsc::channel::<Reply>();

    // Single accept thread. Each accepted connection replaces the previous one.
    let evt_rx = std::sync::Arc::new(std::sync::Mutex::new(evt_rx));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let req_tx = req_tx.clone();
                    let evt_rx = evt_rx.clone();
                    handle_connection(s, req_tx, evt_rx);
                }
                Err(e) => {
                    // Do NOT break. One failed accept is not a reason to stop
                    // serving forever — that turns a transient error into a
                    // permanently deaf socket, which is the same outcome b5
                    // produced by a different route.
                    eprintln!("hwprivacy-lsm: accept failed: {e} (still listening)");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
        eprintln!("hwprivacy-lsm: accept loop ENDED — no further clients can connect");
    });

    Ok(SocketServer {
        path: path.to_path_buf(),
        requests: req_rx,
        events: evt_tx,
    })
}

/// Serve one client until it disconnects. Blocks the accept thread, which is
/// what enforces "one client at a time".
fn handle_connection(
    stream: UnixStream,
    req_tx: Sender<Incoming>,
    evt_rx: std::sync::Arc<std::sync::Mutex<Receiver<Reply>>>,
) {
    let peer = describe_peer(&stream);
    eprintln!("hwprivacy-lsm: client connected ({peer})");

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("hwprivacy-lsm: cannot clone socket: {e}");
            return;
        }
    };

    // Writer: pumps events and request answers out to the client.
    let (out_tx, out_rx) = std::sync::mpsc::channel::<Reply>();
    let writer_handle = std::thread::spawn(move || {
        while let Ok(msg) = out_rx.recv() {
            match encode_line(&msg) {
                Ok(line) => {
                    if writer.write_all(line.as_bytes()).is_err() {
                        break; // client went away
                    }
                    let _ = writer.flush();
                }
                Err(e) => eprintln!("hwprivacy-lsm: cannot encode reply: {e}"),
            }
        }
    });

    // Forward broadcast events into this connection's writer.
    //
    // `stop` is not optional bookkeeping — without it this thread wedges the
    // whole server. It parks in recv() on the broadcast channel, whose sender
    // is owned by SocketServer and therefore lives as long as the process. So
    // recv() NEVER returns Err, the thread never exits, and the join() at the
    // end of this function blocks forever. The accept loop then never runs
    // again and no further client is ever accepted, while the log cheerfully
    // shows "client disconnected".
    //
    // That was b5, diagnosed 2026-08-19 after it wedged the daemon three times
    // in twenty minutes. It looked intermittent because an incoming camera or
    // mic event would unblock recv() and let the join complete — hence the
    // "~51 second reconnect delay" that was really a stuck accept.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_for_events = stop.clone();
    let out_for_events = out_tx.clone();
    let events_handle = std::thread::spawn(move || {
        let rx = evt_rx.lock().unwrap();
        while !stop_for_events.load(std::sync::atomic::Ordering::SeqCst) {
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(ev) => {
                    if out_for_events.send(ev).is_err() {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // Dropping `rx` here releases the mutex, which is what lets the NEXT
        // connection's events thread take it.
    });

    // Reader: this thread. One JSON object per line.
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hwprivacy-lsm: read error: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let _ = out_tx.send(Reply::Error {
                    message: format!("malformed request: {e}"),
                });
                continue;
            }
        };

        // Version check before anything is acted on.
        if let Request::Hello { version } = &req {
            if *version != PROTO_VERSION {
                let _ = out_tx.send(Reply::Error {
                    message: format!(
                        "protocol version mismatch: client {version}, server {PROTO_VERSION}"
                    ),
                });
                break;
            }
        }

        let (rep_tx, rep_rx) = std::sync::mpsc::channel::<Reply>();
        if req_tx.send((req, rep_tx)).is_err() {
            break; // main loop is gone
        }
        // The main loop answers between ring-buffer polls, so this is bounded
        // by the poll interval, not unbounded.
        match rep_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(rep) => {
                if out_tx.send(rep).is_err() {
                    break;
                }
            }
            // These two are NOT the same failure and must not report as one.
            // Timeout means the main loop is alive but slow. Disconnected means
            // it dropped the reply channel — it exited, or the handler died —
            // and the request was never answered at all.
            //
            // They were conflated as "timed out", and on 2026-08-19 that cost a
            // debugging cycle: a disconnect arriving in 0.22s was read as a
            // 5-second timeout, which pointed the investigation at slow I/O
            // that did not exist.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = out_tx.send(Reply::Error {
                    message: "the enforcement thread did not answer within 5s".into(),
                });
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = out_tx.send(Reply::Error {
                    message: "the enforcement thread stopped without answering — \
                              it exited or the request handler died"
                        .into(),
                });
                break;
            }
        }
    }

    eprintln!("hwprivacy-lsm: client disconnected ({peer})");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(out_tx);
    let _ = writer_handle.join();
    let _ = events_handle.join();
    eprintln!("hwprivacy-lsm: ready for the next client");
}

/// Who is on the other end, via `SO_PEERCRED`.
///
/// `UnixStream::peer_cred()` is still unstable on Rust 1.85 (the Debian 13
/// MSRV this project is pinned to), and it only wraps this getsockopt anyway.
/// Worth having beyond logging: the kernel attests these credentials, so a
/// future hardening step can refuse any peer that is not the expected uid.
fn describe_peer(stream: &UnixStream) -> String {
    use std::os::fd::AsRawFd;

    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: a valid socket fd, a correctly sized ucred, and its true length.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
            &mut len,
        )
    };

    if rc == 0 {
        format!("uid={} gid={} pid={}", cred.uid, cred.gid, cred.pid)
    } else {
        "credentials unavailable".to_string()
    }
}

/// Resolve a group name to a gid via getgrnam.
fn lookup_gid(group: &str) -> Result<u32> {
    let cname = std::ffi::CString::new(group)?;
    // SAFETY: getgrnam takes a NUL-terminated string and returns a pointer to
    // static storage or NULL. We only read gr_gid before returning.
    let ptr = unsafe { libc::getgrnam(cname.as_ptr()) };
    if ptr.is_null() {
        anyhow::bail!("no such group: {group}");
    }
    Ok(unsafe { (*ptr).gr_gid })
}

fn chown_group(path: &Path, gid: u32) -> Result<()> {
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: valid NUL-terminated path; -1 uid means "leave the owner alone".
    let rc = unsafe { libc::chown(cpath.as_ptr(), u32::MAX, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot chgrp {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// b5, 2026-08-19: after the first client disconnected, the server never
    /// accepted another. The daemon's connect() still succeeded — a unix socket
    /// reports ESTAB as soon as it is in the listen backlog — so it believed it
    /// was connected and blocked forever on a reply that could not come.
    /// Enforcement kept running on the last pushed policy, so nothing looked
    /// broken while every config change silently stopped taking effect.
    ///
    /// The cause was a per-connection events thread parked in recv() on a
    /// channel whose sender lives as long as the process, joined unconditionally
    /// at the end of handle_connection.
    ///
    /// This test connects, disconnects, and connects AGAIN. Before the fix the
    /// second connect is accepted by the kernel but never by us, so the request
    /// never arrives and this times out.
    #[test]
    fn a_second_client_is_accepted_after_the_first_disconnects() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;

        let dir = std::env::temp_dir().join(format!("hwp-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.sock");

        // The user's own group: resolvable, and chown to it needs no privilege.
        // Same approach as resolves_the_users_own_group above.
        let group = match std::env::var("USER") {
            Ok(u) if lookup_gid(&u).is_ok() => u,
            _ => return, // no resolvable group in this environment; nothing to assert
        };

        let server = serve(&path, &group).expect("serve");

        // Stand in for the main loop: answer every request with Pong.
        let requests = server.requests;
        std::thread::spawn(move || {
            while let Ok((_req, rep_tx)) = requests.recv() {
                let _ = rep_tx.send(Reply::Pong);
            }
        });

        let ping = |label: &str| {
            let mut c = UnixStream::connect(&path)
                .unwrap_or_else(|e| panic!("{label}: connect failed: {e}"));
            c.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            c.write_all(b"{\"req\":\"ping\"}\n").unwrap();
            c.flush().unwrap();
            let mut line = String::new();
            let n = BufReader::new(c.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap_or_else(|e| panic!("{label}: read failed (b5 regression): {e}"));
            assert!(n > 0, "{label}: server never answered — b5 has regressed");
            assert!(line.contains("pong"), "{label}: unexpected reply {line}");
        };

        ping("first client");
        // First client is dropped here. The accept loop must come back.
        ping("second client");
        ping("third client");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolves_a_group_that_certainly_exists() {
        // root's group is gid 0 on every Linux system.
        assert_eq!(lookup_gid("root").unwrap(), 0);
    }

    #[test]
    fn a_missing_group_is_an_error_not_a_silent_fallback() {
        // Falling back to root-only would leave the daemon unable to connect
        // with no explanation — the failure must be loud.
        let e = lookup_gid("definitely-not-a-real-group-xyzzy");
        assert!(e.is_err());
        assert!(format!("{:#}", e.unwrap_err()).contains("no such group"));
    }

    #[test]
    fn resolves_the_users_own_group() {
        // The daemon connects as this group, so it must resolve.
        if let Ok(name) = std::env::var("USER") {
            if let Ok(gid) = lookup_gid(&name) {
                assert!(gid > 0, "a user group should not be gid 0");
            }
        }
    }
}
