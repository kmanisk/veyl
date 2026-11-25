//! Authenticated, bounded Linux IPC, serviced by the existing runner loop.

use std::io::{self, ErrorKind, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;
use std::process::ChildStdin;
use std::time::Duration;

use rustix::time::{ClockId, clock_gettime};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::http::operator::PolicyFile;

use crate::jobs::{invalid, logs, now, store};

use super::terminal::Terminal;

pub(super) const MAX_INPUT: usize = 4096;
const TAG: usize = 32;
const CORRELATION: usize = 16;
const SEQUENCE: usize = TAG + CORRELATION;
const DEADLINE: usize = SEQUENCE + 8;
const EXPIRATION: usize = DEADLINE + 8;
const REVISION: usize = EXPIRATION + 8;
const HEADER: usize = REVISION + 32 + 1;
const REPLY: usize = SEQUENCE + 8 + 8;
const EXCHANGE: Duration = Duration::from_millis(750);

pub(super) enum Operation<'a> {
    Query,
    Write(u64, &'a [u8]),
    Eof(u64),
    Resize(u16, u16),
}

#[repr(u8)]
#[derive(PartialEq)]
enum Outcome {
    Current,
    Accepted,
    Consumed,
    OutOfOrder,
    Backpressure,
    Closed,
    Hangup,
    Revoked,
    NotPty,
    ResizeFailed,
}

impl Outcome {
    const ALL: [Self; 10] = [
        Self::Current, Self::Accepted, Self::Consumed, Self::OutOfOrder,
        Self::Backpressure, Self::Closed, Self::Hangup, Self::Revoked, Self::NotPty, Self::ResizeFailed,
    ];

    fn label(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Accepted => "accepted",
            Self::Consumed => "sequence_consumed",
            Self::OutOfOrder => "out_of_order",
            Self::Backpressure => "backpressure",
            Self::Closed => "closed",
            Self::Hangup => "hangup",
            Self::Revoked => "policy_changed",
            Self::NotPty => "not_pty",
            Self::ResizeFailed => "resize_failed",
        }
    }
}

fn address(prefix: &str, suffix: &[u8]) -> io::Result<SocketAddr> {
    SocketAddr::from_abstract_name(format!("{prefix}{}", store::hex(suffix)).as_bytes())
}

fn session_address(key: &[u8; 32]) -> io::Result<SocketAddr> {
    address("veyl.stdin.", &store::hmac(key, b"endpoint/v1"))
}

fn number(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("wire field is eight bytes"))
}

fn millis() -> u64 {
    let time = clock_gettime(ClockId::Monotonic);
    time.tv_sec as u64 * 1000 + time.tv_nsec as u64 / 1_000_000
}

fn sign(key: &[u8; 32], packet: &mut [u8]) {
    let tag = store::hmac(key, &packet[TAG..]);
    packet[..TAG].copy_from_slice(&tag);
}

fn authentic(key: &[u8; 32], packet: &[u8]) -> bool {
    bool::from(store::hmac(key, &packet[TAG..]).ct_eq(&packet[..TAG]))
}

/// No delivery retry occurs here, including when the acknowledgment is lost.
pub(super) fn exchange(
    key: &[u8; 32],
    revision: &[u8; 32],
    expires_at: u64,
    operation: Operation<'_>,
) -> io::Result<Value> {
    let mut correlation = [0; CORRELATION];
    getrandom::fill(&mut correlation).map_err(|_| invalid())?;
    let client = UnixDatagram::bind_addr(&address("veyl.stdin.reply.", &correlation)?)?;
    client.connect_addr(&session_address(key)?)?;
    client.set_write_timeout(Some(EXCHANGE))?;
    client.set_read_timeout(Some(EXCHANGE))?;

    let deadline = millis() + EXCHANGE.as_millis() as u64;
    let transfer = |kind: u8, sequence: u64, data: &[u8]| -> io::Result<Value> {
        let mut packet = Vec::with_capacity(HEADER + data.len());
        packet.extend_from_slice(&[0; TAG]);
        packet.extend_from_slice(&correlation);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&deadline.to_be_bytes());
        packet.extend_from_slice(&expires_at.to_be_bytes());
        packet.extend_from_slice(revision);
        packet.push(kind);
        packet.extend_from_slice(data);
        sign(key, &mut packet);
        if client.send(&packet)? != packet.len() {
            return Err(invalid());
        }
        let mut reply = [0; REPLY + 1];
        if client.recv(&mut reply)? != REPLY
            || reply[TAG..SEQUENCE] != correlation
            || reply[SEQUENCE + 8] != kind
            || !authentic(key, &reply[..REPLY])
        {
            return Err(invalid());
        }
        let outcome = Outcome::ALL
            .get(usize::from(reply[SEQUENCE + 9]))
            .ok_or_else(invalid)?;
        if *outcome == Outcome::Revoked {
            return Err(io::Error::from(ErrorKind::PermissionDenied));
        }
        if *outcome == Outcome::NotPty {
            return Err(io::Error::new(ErrorKind::InvalidInput, "Session is not a PTY"));
        }
        if *outcome == Outcome::ResizeFailed { return Err(io::Error::other("PTY resize failed")); }
        Ok(json!({
            "status": outcome.label(),
            "next_sequence": number(&reply[SEQUENCE..SEQUENCE + 8]),
            "stdin_closed": reply[SEQUENCE + 10] != 0,
            "pty": reply[SEQUENCE + 11] != 0,
            "rows": if reply[SEQUENCE + 11] != 0 { Some(u16::from_be_bytes([reply[SEQUENCE + 12], reply[SEQUENCE + 13]])) } else { None },
            "cols": if reply[SEQUENCE + 11] != 0 { Some(u16::from_be_bytes([reply[SEQUENCE + 14], reply[SEQUENCE + 15]])) } else { None },
        }))
    };
    // A local peer could reuse an abstract name after its original socket
    // closes. Require proof before sending any input bytes. A connected
    // Unix datagram pins the proved peer socket for the subsequent send.
    let current = transfer(0, 0, &[])?;
    if current["status"] != Outcome::Current.label() {
        return Err(invalid());
    }
    match operation {
        Operation::Query => Ok(current),
        Operation::Write(sequence, data) => transfer(1, sequence, data),
        Operation::Eof(sequence) => transfer(2, sequence, &[]),
        Operation::Resize(rows, cols) => transfer(3, 0, &[rows.to_be_bytes(), cols.to_be_bytes()].concat()),
    }
}

pub(in crate::jobs) enum Input {
    Pipe(ChildStdin),
    Pty(Terminal),
}

pub(in crate::jobs) struct Channel {
    socket: UnixDatagram,
    key: [u8; 32],
    stdin: Option<Input>,
    next: u64,
    pty: bool,
    size: Option<(u16, u16)>,
}

impl Channel {
    pub(in crate::jobs) fn open(key: [u8; 32], stdin: Input) -> io::Result<Self> {
        if let Input::Pipe(pipe) = &stdin {
            logs::nonblocking(pipe)?;
        }
        let socket = UnixDatagram::bind_addr(&session_address(&key)?)?;
        socket.set_nonblocking(true)?;
        let pty = matches!(stdin, Input::Pty(_));
        Ok(Self { socket, key, stdin: Some(stdin), next: 0, pty, size: pty.then_some((24, 80)) })
    }

    pub(in crate::jobs) fn drain_terminal(&mut self, log: &mut logs::Log) -> io::Result<bool> {
        if let Some(Input::Pty(terminal)) = &mut self.stdin {
            log.drain(terminal)
        } else {
            log.ended = true;
            Ok(false)
        }
    }

    pub(in crate::jobs) fn step(&mut self, config: &Path) -> io::Result<()> {
        if let Some(Input::Pty(terminal)) = &mut self.stdin
            && terminal.flush().is_err()
        {
            self.stdin = None;
        }
        let mut packet = [0; HEADER + MAX_INPUT + 1];
        let (len, sender) = match self.socket.recv_from(&mut packet) {
            Ok(message) => message,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if !(HEADER..=HEADER + MAX_INPUT).contains(&len)
            || !authentic(&self.key, &packet[..len])
        {
            return Ok(());
        }
        let correlation = &packet[TAG..TAG + CORRELATION];
        // Also bind the reply address to the unique authenticated exchange.
        if sender.as_abstract_name() != address("veyl.stdin.reply.", correlation)?.as_abstract_name()
        {
            return Ok(());
        }
        let sequence = number(&packet[SEQUENCE..DEADLINE]);
        let deadline = number(&packet[DEADLINE..EXPIRATION]);
        let expires_at = number(&packet[EXPIRATION..REVISION]);
        let revision = packet[REVISION..HEADER - 1].try_into().expect("revision field size");
        let outcome = if let Ok(_policy) = PolicyFile::input_snapshot(config, revision)
            && millis() < deadline
            && now() < expires_at
        {
            self.apply(packet[HEADER - 1], sequence, &packet[HEADER..len])
        } else {
            Outcome::Revoked
        };

        let mut reply = [0; REPLY];
        reply[TAG..TAG + CORRELATION].copy_from_slice(correlation);
        reply[SEQUENCE..SEQUENCE + 8].copy_from_slice(&self.next.to_be_bytes());
        reply[SEQUENCE + 8] = packet[HEADER - 1];
        reply[SEQUENCE + 9] = outcome as u8;
        reply[SEQUENCE + 10] = u8::from(self.stdin.is_none());
        reply[SEQUENCE + 11] = u8::from(self.pty);
        if let Some((rows, cols)) = self.size {
            reply[SEQUENCE + 12..SEQUENCE + 14].copy_from_slice(&rows.to_be_bytes());
            reply[SEQUENCE + 14..SEQUENCE + 16].copy_from_slice(&cols.to_be_bytes());
        }
        sign(&self.key, &mut reply);
        // A peer may leave before reading. The accepted sequence stays consumed.
        let _ = self.socket.send_to_addr(&reply, &sender);
        Ok(())
    }

    fn apply(&mut self, kind: u8, sequence: u64, data: &[u8]) -> Outcome {
        if kind == 0 && data.is_empty() {
            return Outcome::Current;
        }
        if kind == 3 && data.len() == 4 {
            if !self.pty { return Outcome::NotPty; }
            let rows = u16::from_be_bytes([data[0], data[1]]);
            let cols = u16::from_be_bytes([data[2], data[3]]);
            if !(1..=512).contains(&rows) || !(1..=512).contains(&cols) { return Outcome::ResizeFailed; }
            return match &self.stdin {
                Some(Input::Pty(terminal)) if terminal.resize(rows, cols).is_ok() => { self.size = Some((rows, cols)); Outcome::Accepted },
                _ => Outcome::ResizeFailed,
            };
        }
        if sequence < self.next {
            return Outcome::Consumed;
        }
        if sequence != self.next || sequence == u64::MAX {
            return Outcome::OutOfOrder;
        }
        let Some(stdin) = &mut self.stdin else {
            return Outcome::Closed;
        };
        if let Input::Pty(terminal) = stdin
            && !terminal.idle()
        {
            return Outcome::Backpressure;
        }
        if kind == 2 && data.is_empty() {
            let terminal = matches!(stdin, Input::Pty(_));
            self.stdin = None;
            self.next += 1;
            return if terminal { Outcome::Hangup } else { Outcome::Accepted };
        }
        if kind != 1 || data.is_empty() {
            return Outcome::Closed;
        }
        let pipe = match stdin {
            Input::Pipe(pipe) => pipe,
            Input::Pty(terminal) => {
                terminal.enqueue(data);
                self.next += 1;
                return Outcome::Accepted;
            }
        };
        // A Linux nonblocking pipe write of <= PIPE_BUF is all-or-nothing.
        // Never retry an uncertain or partial write.
        match pipe.write(data) {
            Ok(n) if n == data.len() => {
                self.next += 1;
                Outcome::Accepted
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                Outcome::Backpressure
            }
            _ => {
                self.stdin = None;
                Outcome::Closed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unproved_peer_never_receives_input() -> io::Result<()> {
        let mut key = [0; 32];
        getrandom::fill(&mut key).map_err(|_| invalid())?;
        let peer = UnixDatagram::bind_addr(&session_address(&key)?)?;
        peer.set_read_timeout(Some(Duration::from_millis(950)))?;
        let impostor = std::thread::spawn(move || -> io::Result<()> {
            let mut message = [0; HEADER + MAX_INPUT + 1];
            let (length, sender) = peer.recv_from(&mut message)?;
            assert_eq!(length, HEADER);
            assert_eq!(message[HEADER - 1], 0);
            let mut reply = [0; REPLY];
            reply[TAG..SEQUENCE].copy_from_slice(&message[TAG..SEQUENCE]);
            peer.send_to_addr(&reply, &sender)?;
            peer.set_read_timeout(Some(Duration::from_millis(180)))?;
            assert_eq!(peer.recv(&mut message).unwrap_err().kind(), ErrorKind::WouldBlock);
            Ok(())
        });
        let result = exchange(&key, &[0; 32], now() + 5, Operation::Write(0, b"private input"));
        impostor.join().expect("impostor test thread")?;
        assert!(result.is_err());
        Ok(())
    }
}
