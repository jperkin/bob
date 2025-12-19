/*
 * Copyright (c) 2025 Jonathan Perkin <jonathan@perkin.org.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Status channel for communication between pkg-build and the master process.
 *
 * Uses a Unix pipe to send status messages from the build script to the
 * master. Messages are simple line-based text:
 *   stage:<name>  - build entered a new stage
 *   skipped       - package was skipped (up-to-date)
 */

use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

/// A status message from the build script.
#[derive(Debug, Clone, PartialEq)]
pub enum StatusMessage {
    Stage(String),
    Skipped,
}

impl StatusMessage {
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if let Some(stage) = line.strip_prefix("stage:") {
            Some(StatusMessage::Stage(stage.to_string()))
        } else if line == "skipped" {
            Some(StatusMessage::Skipped)
        } else {
            None
        }
    }
}

/// Read end of the status channel.
pub struct StatusReader {
    reader: BufReader<os_pipe::PipeReader>,
}

impl StatusReader {
    /// Read a status message (non-blocking, returns None if no data available).
    pub fn try_read(&mut self) -> Option<StatusMessage> {
        let mut line = String::new();
        // Set non-blocking
        let fd = self.reader.get_ref().as_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        match self.reader.read_line(&mut line) {
            Ok(0) => None, // EOF
            Ok(_) => StatusMessage::parse(&line),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    /// Read all available messages.
    pub fn read_all(&mut self) -> Vec<StatusMessage> {
        let mut messages = Vec::new();
        while let Some(msg) = self.try_read() {
            messages.push(msg);
        }
        messages
    }
}

/// Write end of the status channel (passed to child process).
pub struct StatusWriter {
    fd: RawFd,
}

impl StatusWriter {
    /// Get the file descriptor number to pass to the child.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Consume and close the writer (after fork, the parent should close this).
    pub fn close(self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Create a status channel pair.
pub fn channel() -> Result<(StatusReader, StatusWriter)> {
    let (reader, writer) = os_pipe::pipe().context("Failed to create status pipe")?;

    // Clear O_CLOEXEC on the write end so it survives exec
    let write_fd = writer.into_raw_fd();
    unsafe {
        let flags = libc::fcntl(write_fd, libc::F_GETFD);
        libc::fcntl(write_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }

    Ok((
        StatusReader {
            reader: BufReader::new(reader),
        },
        StatusWriter { fd: write_fd },
    ))
}
