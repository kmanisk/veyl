//! Bounded synchronous execution of a fixed, locally chosen program.

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    process::{Pid, Signal, kill_process_group},
};
use std::{
    io::{self, Read, Write},
    os::unix::process::CommandExt,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn capture_with_input(
    command: &mut Command,
    input: &[u8],
    limit: usize,
    timeout: Duration,
) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;
    let mut stdin = child.stdin.take();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let result = (|| {
        if let Some(ref s) = stdin {
            fcntl_setfl(s, fcntl_getfl(s)? | OFlags::NONBLOCK)?;
        }
        if let Some(ref p) = stdout_pipe {
            fcntl_setfl(p, fcntl_getfl(p)? | OFlags::NONBLOCK)?;
        }
        if let Some(ref p) = stderr_pipe {
            fcntl_setfl(p, fcntl_getfl(p)? | OFlags::NONBLOCK)?;
        }
        let mut written = 0;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        while stdin.is_some() || stdout_pipe.is_some() || stderr_pipe.is_some() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if let Some(ref mut writer) = stdin {
                if written < input.len() {
                    match writer.write(&input[written..]) {
                        Ok(0) => stdin = None,
                        Ok(n) => {
                            written += n;
                            if written == input.len() {
                                stdin = None;
                            }
                        }
                        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => (),
                        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => stdin = None,
                        Err(e) => return Err(e),
                    }
                } else {
                    stdin = None;
                }
            }
            let drain = |slot: &mut Option<std::process::ChildStdout>, out: &mut Vec<u8>, total: usize| -> io::Result<bool> {
                let Some(reader) = slot.as_mut() else { return Ok(false); };
                let mut buffer = [0; 4096];
                match reader.read(&mut buffer) {
                    Ok(0) => { *slot = None; Ok(true) }
                    Ok(n) if total.saturating_add(n) > limit => Err(io::Error::other("Command output exceeded limit")),
                    Ok(n) => { out.extend_from_slice(&buffer[..n]); Ok(true) }
                    Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(false),
                    Err(e) => Err(e),
                }
            };
            let drain_err = |slot: &mut Option<std::process::ChildStderr>, out: &mut Vec<u8>, total: usize| -> io::Result<bool> {
                let Some(reader) = slot.as_mut() else { return Ok(false); };
                let mut buffer = [0; 4096];
                match reader.read(&mut buffer) {
                    Ok(0) => { *slot = None; Ok(true) }
                    Ok(n) if total.saturating_add(n) > limit => Err(io::Error::other("Command output exceeded limit")),
                    Ok(n) => { out.extend_from_slice(&buffer[..n]); Ok(true) }
                    Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(false),
                    Err(e) => Err(e),
                }
            };
            let total = stdout.len() + stderr.len();
            let progressed = drain(&mut stdout_pipe, &mut stdout, total)?;
            let total = stdout.len() + stderr.len();
            let progressed = drain_err(&mut stderr_pipe, &mut stderr, total)? | progressed;
            if progressed || (stdin.is_some() && written < input.len()) {
                continue;
            }
            let mut fds = Vec::new();
            if let Some(ref s) = stdin {
                fds.push(PollFd::new(s, PollFlags::OUT));
            }
            if let Some(ref p) = stdout_pipe {
                fds.push(PollFd::new(p, PollFlags::IN));
            }
            if let Some(ref p) = stderr_pipe {
                fds.push(PollFd::new(p, PollFlags::IN));
            }
            if !fds.is_empty() {
                poll(
                    &mut fds,
                    Some(&Timespec {
                        tv_sec: remaining.as_secs() as i64,
                        tv_nsec: remaining.subsec_nanos().into(),
                    }),
                )?;
            }
        }
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok((status, stdout, stderr));
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        if let Some(pid) = Pid::from_raw(child.id() as i32) {
            let _ = kill_process_group(pid, Signal::KILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

pub(crate) fn capture(
    command: &mut Command,
    limit: usize,
    timeout: Duration,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let mut pipe = child.stdout.take().expect("piped stdout");
    let result = (|| {
        fcntl_setfl(&pipe, fcntl_getfl(&pipe)? | OFlags::NONBLOCK)?;
        let mut output = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) if n > limit.saturating_sub(output.len()) => {
                    return Err(io::Error::other("Command output exceeded limit"));
                }
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut fds = [PollFd::new(&pipe, PollFlags::IN)];
                    poll(
                        &mut fds,
                        Some(&Timespec {
                            tv_sec: remaining.as_secs() as i64,
                            tv_nsec: remaining.subsec_nanos().into(),
                        }),
                    )?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error),
            }
        }
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok((status, output));
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        if let Some(pid) = Pid::from_raw(child.id() as i32) {
            let _ = kill_process_group(pid, Signal::KILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

