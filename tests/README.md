# Test Setup for Port Explorer

This directory contains integration tests for the Port Explorer project.

## How to Add Tests
- Add new test files in this directory (e.g., `scan_tests.rs`, `config_tests.rs`).
- Use Rust's standard `#[test]` attribute for test functions.
- You can import your library code with `use port_explorer::*;` if you expose a library target in `Cargo.toml`.

## Running Tests
Run all tests (unit + integration):
```sh
cargo test
```

Run only integration tests:
```sh
cargo test --test integration_test
```

## Example
See `integration_test.rs` for a basic example.
