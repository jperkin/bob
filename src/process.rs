/*
 * Copyright (c) 2026 Jonathan Perkin <jonathan@perkin.org.uk>
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

/*!
 * Wrapper around std::process::Command.
 *
 * Bob spawns a lot of processes, and many of these calls can be grouped by
 * functionality.  Rather than relying on every call site to correctly construct
 * things, the aim here is to provide a consistent and useful interface that
 * reduces the chances of incorrect programming, as well as having a central
 * hook for things like logging.
 */

use std::ffi::OsStr;
use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Output, Stdio};

#[cfg(target_os = "macos")]
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/**
 * Spawn wrapper to avoid race condition on macOS versions that lack pipe2().
 *
 * During process creation the close-on-exec flag is set.  On most systems this
 * can be done atomically using pipe2().  Unfortunately macOS at least up to
 * version 27 does not support this, and so there is a window between the
 * separate system calls where processes can inherit a file descriptor that is
 * left unclosed.
 *
 * This primarily exhibits as hangs during parallel sandbox creation where an
 * inherited pipe writer prevents EOF.
 *
 * To avoid this race condition we have a mutex lock around the initial spawn.
 */
pub fn with_spawn_lock<T>(launch: impl FnOnce() -> T) -> T {
    #[cfg(target_os = "macos")]
    let _guard = match LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    launch()
}

macro_rules! forward {
    ($($method:ident($($arg:ident: $ty:ty),*) $(=> $flag:ident)?;)*) => {$(
        pub fn $method(&mut self, $($arg: $ty),*) -> &mut Self {
            self.command.$method($($arg),*);
            $(self.$flag = true;)?
            self
        }
    )*};
}

pub struct Process {
    command: Command,
    stdin: bool,
    stdout: bool,
    stderr: bool,
}
impl std::fmt::Debug for Process {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.command.fmt(formatter)
    }
}
impl Process {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            command: Command::new(program),
            stdin: false,
            stdout: false,
            stderr: false,
        }
    }
    forward! {
        arg(arg: impl AsRef<OsStr>);
        args(args: impl IntoIterator<Item = impl AsRef<OsStr>>);
        env(name: impl AsRef<OsStr>, value: impl AsRef<OsStr>);
        envs(envs: impl IntoIterator<Item = (impl AsRef<OsStr>, impl AsRef<OsStr>)>);
        env_clear();
        current_dir(path: impl AsRef<std::path::Path>);
        process_group(group: i32);
        stdin(stream: impl Into<Stdio>) => stdin;
        stdout(stream: impl Into<Stdio>) => stdout;
        stderr(stream: impl Into<Stdio>) => stderr;
    }

    pub fn new_session(&mut self) -> &mut Self {
        unsafe {
            self.command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        self
    }
    fn launch(&mut self, capture: bool) -> io::Result<Child> {
        let input: fn() -> Stdio = if capture { Stdio::null } else { Stdio::inherit };
        let output: fn() -> Stdio = if capture {
            Stdio::piped
        } else {
            Stdio::inherit
        };
        if !self.stdin {
            self.command.stdin(input());
        }
        if !self.stdout {
            self.command.stdout(output());
        }
        if !self.stderr {
            self.command.stderr(output());
        }
        with_spawn_lock(|| self.command.spawn())
    }
    pub fn spawn(&mut self) -> io::Result<Child> {
        self.launch(false)
    }
    pub fn output(&mut self) -> io::Result<Output> {
        self.launch(true)?.wait_with_output()
    }
    pub fn status(&mut self) -> io::Result<ExitStatus> {
        self.spawn()?.wait()
    }
}
