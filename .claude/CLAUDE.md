# Bob - pkgsrc Package Builder

A utility for building pkgsrc packages with automatic sandboxing, parallel
builds, and resumable operations.

## Philosophy

Perfection is achieved not when there is nothing more to add, but when there
is nothing left to remove.

## Critical Rules

- Code must pass `cargo clippy` and `cargo fmt`
- Never use `unwrap()`, even in tests - use `?` with Result-returning functions
- Preserve existing code style, including `/** */` comment blocks
- Comments only for complex logic, not obvious operations
- Keep changes minimal and focused - no over-engineering

## Build & Verify

```bash
cargo build
cargo fmt -- --check
cargo clippy
cargo test
```

## Quick Reference

| Module | Purpose |
|--------|---------|
| main.rs | CLI entry, BuildRunner |
| config.rs | Lua configuration |
| scan.rs | Dependency scanning |
| build.rs | Parallel builds |
| db.rs | SQLite caching |
| sandbox.rs | Platform abstraction |

See `.claude/rules/` for detailed guides.
