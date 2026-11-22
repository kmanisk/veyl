//! Capped, nonblocking per-stream capture and bounded MCP excerpts.

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};

use rustix::fd::AsFd;
use rustix::fs::{self, OFlags};
use serde_json::{Value, json};

use super::receipt::Receipt;
use super::store::JobDir;

pub(super) const EXCERPT_BYTES: usize = 4096;

pub(super) struct Log {
    file: File,
    remaining: usize,
    pub truncated: bool,
    pub ended: bool,
}

impl Log {
    pub fn open(job: &JobDir<'_>, name: &'static str, limit: usize) -> io::Result<Self> {
        Ok(Self {
            file: job.open_log(name, OFlags::WRONLY)?,
            remaining: limit,
            truncated: false,
            ended: false,
        })
    }

    pub fn drain(&mut self, pipe: &mut impl Read) -> io::Result<bool> {
        if self.ended {
            return Ok(false);
        }
        let mut buffer = [0; 8192];
        let mut progress = false;
        // Budget each pass so a noisy child cannot starve timeout or cancel.
        for _ in 0..8 {
            let read = match pipe.read(&mut buffer) {
                Ok(0) => {
                    self.ended = true;
                    break;
                }
                Ok(read) => read,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            progress = true;
            let retain = self.remaining.min(read);
            self.remaining -= retain;
            self.truncated |= retain < read;
            self.file.write_all(&buffer[..retain])?;
        }
        Ok(progress)
    }

    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    pub fn retained_bytes(&self, limit: usize) -> usize {
        limit.saturating_sub(self.remaining)
    }
}

pub(super) fn nonblocking(pipe: impl AsFd) -> io::Result<()> {
    let flags = fs::fcntl_getfl(&pipe)? | OFlags::NONBLOCK;
    fs::fcntl_setfl(&pipe, flags)?;
    Ok(())
}

pub(super) fn excerpts(job: &JobDir<'_>, receipt: &Receipt) -> io::Result<Value> {
    let limit = EXCERPT_BYTES.min(receipt.max_output_bytes);
    let stdout = excerpt(job, "stdout.log", limit, receipt.stdout_truncated)?;
    let stderr = excerpt(job, "stderr.log", limit, receipt.stderr_truncated)?;
    Ok(json!({
        "job_id": receipt.job_id,
        "stdout": stdout.0, "stderr": stderr.0,
        "stdout_truncated": stdout.1, "stderr_truncated": stderr.1,
    }))
}

fn excerpt(
    job: &JobDir<'_>,
    name: &'static str,
    limit: usize,
    truncated: bool,
) -> io::Result<(String, bool)> {
    let mut bytes = Vec::new();
    job.open_log(name, OFlags::RDONLY)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    let truncated = truncated || bytes.len() > limit;
    bytes.truncate(limit);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}
