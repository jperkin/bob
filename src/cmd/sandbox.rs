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

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};

use bob::config::{Config, PkgsrcEnv};
use bob::sandbox::Sandbox;

pub fn exec(config: &Config) -> Result<()> {
    let sandbox = Sandbox::new(config);
    if !sandbox.enabled() {
        bail!("No sandboxes configured");
    }
    let id = sandbox.next_available_id()?;
    print!("Creating sandbox...");
    let _ = std::io::stdout().flush();
    let start = Instant::now();
    sandbox.create(id)?;
    let basic_envs = config.script_env(None);
    let result = (|| -> Result<()> {
        if !sandbox.run_pre_build(id, config, basic_envs)? {
            println!(" failed ({:.1}s)", start.elapsed().as_secs_f32());
            bail!("pre-build script failed");
        }
        println!(" done ({:.1}s)", start.elapsed().as_secs_f32());
        println!("Entering sandbox {}...", sandbox.path(id).display());
        let mut cmd = Command::new("/usr/sbin/chroot");
        cmd.arg(sandbox.path(id)).arg("/bin/sh").arg("-i");
        sandbox.apply_environment(&mut cmd);
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = cmd.status().context("Failed to run chroot shell")?;
        if !status.success() {
            bail!("Shell exited with {}", status);
        }
        Ok(())
    })();
    let pkgsrc_env = PkgsrcEnv::fetch(config, &sandbox, id).ok();
    let envs = config.script_env(pkgsrc_env.as_ref());
    sandbox.run_post_build(id, config, envs)?;
    print!("Destroying sandbox...");
    let _ = std::io::stdout().flush();
    let start = Instant::now();
    sandbox.destroy(id)?;
    println!(" done ({:.1}s)", start.elapsed().as_secs_f32());
    result
}
