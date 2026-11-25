//! Allocate a dedicated kernel PTY without reopening a host pathname for its slave.

use std::fs::File;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

use rustix::io::Errno;
use rustix::pty::{OpenptFlags, ioctl_tiocgptpeer, openpt, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

use crate::jobs::logs;

pub(in crate::jobs) const SETSID: &str = "/usr/bin/setsid";

pub(in crate::jobs) struct Terminal {
    master: File,
    pending: Option<(Vec<u8>, usize)>,
}

impl Terminal {
    pub(in crate::jobs) fn attach(command: &mut Command) -> io::Result<Self> {
        let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let master = openpt(flags)?;
        unlockpt(&master)?;
        let slave = File::from(ioctl_tiocgptpeer(&master, flags)?);
        rustix::fs::fchmod(&slave, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)?;
        tcsetwinsize(
            &master,
            Winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )?;
        logs::nonblocking(&master)?;
        command
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        Ok(Self {
            master: File::from(master),
            pending: None,
        })
    }

    pub(super) fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        tcsetwinsize(
            &self.master,
            Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )?;
        Ok(())
    }

    pub(super) fn idle(&self) -> bool {
        self.pending.is_none()
    }

    pub(super) fn enqueue(&mut self, bytes: &[u8]) {
        self.pending = Some((bytes.to_vec(), 0));
    }

    /// PTY writes can be partial. Retain at most one admitted frame and
    /// advance its cursor once per successful nonblocking write.
    pub(super) fn flush(&mut self) -> io::Result<()> {
        if let Some((bytes, used)) = &mut self.pending {
            match self.master.write(&bytes[*used..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(n) => {
                    *used += n;
                    if *used == bytes.len() {
                        self.pending = None;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl Read for Terminal {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.master.read(buffer) {
            Err(e) if e.raw_os_error() == Some(Errno::IO.raw_os_error()) => Ok(0),
            result => result,
        }
    }
}
