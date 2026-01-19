# Rust Code Style

## Formatting

- 80 character line width (enforced via `.rustfmt.toml`)
- Run `cargo fmt` before committing
- Edition 2024, MSRV 1.85.1

## Error Handling

Use `anyhow` for error propagation:

```rust
use anyhow::{Context, Result, bail};

// Propagate with context
let db = Database::open(&path).context("Failed to open database")?;

// Early return with error
if packages.is_empty() {
    bail!("No packages to build");
}

// Never use unwrap - this is forbidden
let db = Database::open(&path).unwrap();  // WRONG
```

## Comments

Doc comment style:
- Module docs: `/*! */` multi-line block style
- Item docs: `/** */` multi-line block style (never single-line)
- Do not use `//!` or `///` style

```rust
/*!
 * Module-level documentation goes here.
 */

/**
 * Function or type documentation.
 */
pub fn example() {}
```

General comments:
- Only add comments for complex logic
- Avoid trivial comments like "increment counter"
- If tempted to comment, consider rewriting for clarity instead

```rust
// WRONG - unnecessary comment
// Add 1 to the counter
count += 1;

// RIGHT - explains non-obvious logic
// Skip bootstrap packages as they're handled separately by the pre-build script
if pkg.is_bootstrap() {
    continue;
}
```

## Concurrency Patterns

### Shutdown Flag
Always check in loops:
```rust
if self.ctx.shutdown.load(Ordering::SeqCst) {
    return Ok(());
}
```

### RAII for Resources
```rust
let scope = SandboxScope::new(sandbox, threads, verbose)?;
// Automatic cleanup on drop - never manually destroy
```

### Database Transactions
```rust
self.db.begin_transaction()?;
// ... operations ...
self.db.commit()?;
```

## Imports

Group imports in this order:
1. `std` library
2. External crates
3. Internal crates (`crate::`, `super::`)

```rust
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use crate::config::Config;
use crate::db::Database;
```

## Naming

- Types: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Modules: `snake_case`

## Platform-Specific Code

Use conditional compilation:
```rust
#[cfg(target_os = "linux")]
mod sandbox_linux;

#[cfg(target_os = "linux")]
pub use sandbox_linux::*;
```
