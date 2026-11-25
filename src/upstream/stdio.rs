use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fd::AsFd;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use serde_json::Value;

use super::MAX_FRAME;

pub(super) struct Process {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}

impl Process {
    pub fn start(
        command: &str,
        args: &[String],
        bundle: Option<&std::path::Path>,
        workspace: Option<&super::workspace::Input>,
    ) -> io::Result<Self> {
        let mut worker = Command::new(std::env::current_exe()?);
        worker.arg("--mcp-upstream-worker");
        if let Some(bundle) = bundle {
            worker.arg("--runtime-bundle").arg(bundle);
        }
        if let Some(input) = workspace {
            worker
                .arg("--workspace-input")
                .arg(&input.root)
                .arg(input.identity[0].to_string())
                .arg(input.identity[1].to_string())
                .arg(&input.relative)
                .arg(if input.tree { "tree" } else { "file" });
        }
        let mut child = worker
            .arg(command)
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
        let input = child.stdin.take().expect("piped stdin");
        let output = child.stdout.take().expect("piped stdout");
        let process = Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
        };
        for fd in [
            process.input.as_ref().unwrap().as_fd(),
            process.output.get_ref().as_fd(),
        ] {
            fcntl_setfl(fd, fcntl_getfl(fd)? | OFlags::NONBLOCK)?;
        }
        Ok(process)
    }

    pub fn send(&mut self, message: &Value, deadline: Instant) -> io::Result<()> {
        let mut payload = serde_json::to_vec(message)?;
        if payload.len() >= MAX_FRAME {
            return Err(io::Error::other("MCP message too large"));
        }
        payload.push(b'\n');
        let mut data = payload.as_slice();
        let input = self.input.as_mut().expect("open stdin");
        while !data.is_empty() {
            wait(input.as_fd(), PollFlags::OUT, deadline)?;
            match input.write(data) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => data = &data[n..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn read(&mut self, deadline: Instant, remaining: &mut usize) -> io::Result<Value> {
        let mut frame = Vec::new();
        loop {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let bytes = match self.output.fill_buf() {
                Ok([]) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.output.get_ref().as_fd(), PollFlags::IN, deadline)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let end = bytes.iter().position(|&byte| byte == b'\n');
            let n = end.map_or(bytes.len(), |idx| idx + 1);
            if n > *remaining || frame.len() + n > MAX_FRAME {
                return Err(io::Error::other("MCP response too large"));
            }
            *remaining -= n;
            frame.extend_from_slice(&bytes[..n]);
            self.output.consume(n);
            if end.is_some() {
                return Ok(serde_json::from_slice(&frame)?);
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        drop(self.input.take());
        if self.child.try_wait().ok().flatten().is_none() {
            // The outer launcher is the Bubblewrap supervisor. PID namespace
            // teardown also removes peers or descendants in separate groups.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait(fd: impl AsFd, events: PollFlags, deadline: Instant) -> io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining == Duration::ZERO {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let timeout = rustix::event::Timespec {
        tv_sec: remaining.as_secs() as i64,
        tv_nsec: i64::from(remaining.subsec_nanos()),
    };
    let mut fds = [PollFd::new(&fd, events)];
    if poll(&mut fds, Some(&timeout))? == 0 {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}
