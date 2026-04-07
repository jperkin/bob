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

use std::fmt::Write as _;
use std::fs;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::Subcommand;

use bob::config::{Config, PkgsrcEnv};
use bob::logging;
use bob::sandbox::Sandbox;

#[derive(Debug, Subcommand)]
pub enum SandboxCmd {
    /// Create all sandboxes
    Create,
    /// Destroy all sandboxes
    Destroy,
    /// Create a sandbox and start an interactive shell
    Exec,
    /// List currently created sandboxes
    List,
}

pub fn run(config: &Config, cmd: SandboxCmd) -> Result<()> {
    match cmd {
        SandboxCmd::Create => {
            logging::init_stderr_if_enabled();
            let sandbox = Sandbox::new(config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.create_all(config.build_threads())?;
        }
        SandboxCmd::Destroy => {
            logging::init_stderr_if_enabled();
            let sandbox = Sandbox::new(config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            let pkgsrc_env = bob::Database::open(config.dbdir())
                .and_then(|db| db.load_pkgsrc_env())
                .ok();
            if pkgsrc_env.is_none() {
                eprintln!("Warning: No database available, unable to remove pkgsrc directories.");
            }
            sandbox.destroy_all(pkgsrc_env.as_ref())?;
        }
        SandboxCmd::Exec => {
            logging::init(config.dbdir(), config.log_level())?;
            exec(config)?;
        }
        SandboxCmd::List => {
            let sandbox = Sandbox::new(config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.list_all()?;
        }
    }
    Ok(())
}

fn exec(config: &Config) -> Result<()> {
    let sandbox = Sandbox::new_dev(config);
    if !sandbox.enabled() {
        bail!("No sandboxes configured");
    }
    bob::print_status("Creating sandbox");
    let start = Instant::now();
    let id = sandbox.claim_id()?;
    let basic_envs = config.script_env(None);
    let result = (|| -> Result<()> {
        if !sandbox.run_pre_build(Some(id), config, basic_envs)? {
            bob::print_elapsed("Creating sandbox", start.elapsed());
            bail!("pre-build failed");
        }
        bob::print_elapsed("Creating sandbox", start.elapsed());
        let pkgsrc_env = PkgsrcEnv::fetch(config, &sandbox, Some(id))?;
        let init_path = write_shell_init(config, &sandbox, &pkgsrc_env, id)?;
        println!("Entering sandbox {}...", sandbox.path(id).display());
        let mut cmd = Command::new("/usr/sbin/chroot");
        cmd.arg(sandbox.path(id)).arg("/bin/sh").arg(&init_path);
        sandbox.apply_dev_environment(&mut cmd);
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = cmd.status().context("Failed to run chroot shell")?;
        if !status.success() {
            bail!("Shell exited with {}", status);
        }
        Ok(())
    })();
    let pkgsrc_env = PkgsrcEnv::fetch(config, &sandbox, Some(id)).ok();
    let envs = config.script_env(pkgsrc_env.as_ref());
    match sandbox.run_post_build(Some(id), config, envs) {
        Ok(true) => {}
        Ok(false) => eprintln!("Warning: post-build failed"),
        Err(e) => eprintln!("Warning: post-build error: {e}"),
    }
    bob::print_status("Destroying sandbox");
    let start = Instant::now();
    sandbox.destroy(id)?;
    bob::print_elapsed("Destroying sandbox", start.elapsed());
    result
}

/**
 * Write the shell init wrapper script to `<sandbox>/.bob/shell-init`.
 *
 * The wrapper exports all `bob_*` variables (defensively double-quoted
 * by bob, since they may contain whitespace), then exports each variable
 * from the `environment.dev.vars` config table verbatim -- the user is
 * responsible for any shell quoting.  Finally it removes itself and
 * execs the configured interactive shell (`environment.dev.shell`,
 * defaulting to `/bin/sh`).  Returning the path inside the chroot lets
 * the caller invoke `chroot <path> /bin/sh /.bob/shell-init`.
 */
fn write_shell_init(
    config: &Config,
    sandbox: &Sandbox,
    pkgsrc_env: &PkgsrcEnv,
    id: usize,
) -> Result<String> {
    let dev_ctx = config.environment().and_then(|e| e.dev.as_ref());
    let interactive_shell = dev_ctx
        .and_then(|c| c.shell.as_ref())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/bin/sh".to_string());

    let mut script = String::new();
    script.push_str("#!/bin/sh\n");

    let mut bob_vars = config.script_env(Some(pkgsrc_env));
    bob_vars.push(("bob_sandbox_id".to_string(), id.to_string()));
    bob_vars.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in &bob_vars {
        let _ = writeln!(script, "export {}={}", name, bob_dquote(value));
    }

    if let Some(ctx) = dev_ctx {
        let mut dev_vars: Vec<(&String, &String)> = ctx.vars.iter().collect();
        dev_vars.sort_by(|a, b| a.0.cmp(b.0));
        for (name, value) in dev_vars {
            let _ = writeln!(script, "export {}={}", name, value);
        }
    }

    script.push_str("rm -f /.bob/shell-init\n");
    let _ = writeln!(script, "exec {} -i", interactive_shell);

    let host_path = sandbox.path(id).join(".bob/shell-init");
    fs::write(&host_path, &script)
        .with_context(|| format!("Failed to write {}", host_path.display()))?;
    Ok("/.bob/shell-init".to_string())
}

/**
 * Wrap a `bob_*` value in POSIX shell double quotes with full escaping.
 *
 * Used only for bob's own values, not user-supplied `environment.shell`
 * entries.  These are paths and identifiers that bob constructs, so
 * `$`, backtick, `\`, and `"` are all escaped to make the assignment
 * safe regardless of any unusual characters in the path.
 */
fn bob_dquote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if matches!(c, '"' | '\\' | '`' | '$') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}
