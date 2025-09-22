[![Rust Build](https://github.com/SpiceSniper/port-explorer/actions/workflows/rust.yml/badge.svg)](https://github.com/SpiceSniper/port-explorer/actions/workflows/rust.yml)
# Port Explorer
Port Explorer is a fast network port and service discovery written entirely in Rust!

## Features
- High Performance TCP Port Scanning
- Service Recognition through HTML Header Parsing
- Configurability through config file
- Pluggable signature rules (YAML)

## Getting Started
### Prerequisites
- [Rust toolchain (stable)](https://www.rust-lang.org/tools/install)
- Linux(tested)/macOS(untested)/Windows(untested)

### Build
```sh
cargo build --release
```

### Run
```sh
./target/release/port-explorer <config_path>
```
You can run the program by executing the shell command above. You can optionally pass the path to a config file, if no path is passed or the path is invalid `./config.yaml` is used.

### Configuration
Edit `config.yaml` (or a config file of your choice) to set scan parameters:
- `ip`: Target IP address
- `start_port`, `end_port`: Port range
- `max_threads`: Concurrency
- `language`: Localization (e.g., `en` -> filename with out `.yaml`)

Signatures for service identification are in `signatures/` (YAML files). You can add new yaml files and subfolders into the `signatures/` folder, as it gets parsed recursively. 

Alternatively, all config values can be passed as commandline arguments, which then overwrite their respective config file arguments. Arguments can be used like this: `./target/release/port-explorer --argument <value>`.


## Usage
- Run a scan: `./target/release/port-explorer <config_path>`
- Logs are written to `logs/` with timestamped filenames
- Localization files in `resources/Localization/`


## Project Structure
```
port-explorer/
  ├─ src/
  │   ├─ main.rs             # Entry point
  │   ├─ config.rs           # Config parsing/validation
  │   ├─ signatures.rs       # Signature loading/matching
  │   ├─ error.rs            # Error types
  │   └─ localisator.rs      # Localization
  ├─ signatures/             # Service signature YAMLs
  ├─ resources/Localization/ # Localization YAMLs
  ├─ logs/                   # Scan logs
  ├─ config.yaml             # Main config
  ├─ Cargo.toml              # Rust manifest
  └─ README.md               # This ReadMe
```

## Development
- Standard Rust workflow: `cargo build`, `cargo test`, `cargo fmt`
- Add new signatures in `signatures/`
- Add new languages in `resources/Localization/`

## Contributions
- If you encounter an issue/bug, please open an issue.
- If you have feature requests, feel free to either open a pull request or an issue
- New signatures/localization is always welcome

## Issues and Further Development
- Some signatures may be inaccurate and may not work yet
- Testcases need to be expanded to reach 100% coverage and include integration tests
- Currently no more features are planned, but suggestions are welcome.

## License
MIT License

---
Maintainers: SpiceSniper