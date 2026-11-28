use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::event::{EventfdFlags, eventfd};
use tokio::sync::Notify;

pub(crate) struct Cancellation {
    fd: OwnedFd,
    cancelled: AtomicBool,
    ready: Notify,
}

impl Cancellation {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            fd: eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?,
            cancelled: AtomicBool::new(false),
            ready: Notify::new(),
        })
    }

    pub(crate) fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            let signal = 1_u64.to_ne_bytes();
            while let Err(rustix::io::Errno::INTR) = rustix::io::write(&self.fd, &signal) {}
            self.ready.notify_one();
        }
    }

    pub(super) fn check(&self) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Ok(())
        }
    }

    pub(super) fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    pub(super) async fn wait(&self) {
        if self.check().is_ok() {
            self.ready.notified().await;
        }
    }
}
