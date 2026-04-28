# MimoBox CLI

Command-line interface for [mimobox](https://github.com/showkw/mimobox).

This crate provides the `mimobox` binary for command execution, shells,
snapshots, restores, benchmarks, diagnostics, setup, MCP init, and version info.

`publish = false`; this crate is intended for workspace distribution, not
direct crates.io publication.

## Features

- `wasm`: enables the WebAssembly backend.
- `kvm`: enables the Linux KVM microVM backend.
- `full`: enables all optional CLI backends supported by the workspace.

## Subcommands

- `run`: execute a command in a sandbox.
- `shell`: start an interactive sandbox shell.
- `snapshot`: create a microVM snapshot file.
- `restore`: restore a snapshot and execute a command.
- `bench`: run pool-related benchmarks.
- `doctor`: diagnose the local runtime environment.
- `setup`: initialize local mimobox assets and directories.
- `mcp-init`: configure the MCP server for supported desktop clients.
- `version`: print version information.

## Run Options

`mimobox run` accepts:

- `--backend auto|os|wasm|kvm`
- `--command <cmd>`
- trailing `argv...` for direct argument execution
- `--memory <mb>`
- `--timeout <seconds>`
- `--deny-network` / `--allow-network`
- `--allow-fork`
- `--kernel <path>`
- `--rootfs <path>`
- `--vcpu-count <count>`

## Examples

```sh
mimobox run --command '/bin/echo hello'
mimobox run -- /bin/echo hello
mimobox run --backend kvm --command '/bin/uname -a'
mimobox shell
mimobox doctor
mimobox mcp-init claude
```

## Repository

https://github.com/showkw/mimobox

## License

MIT OR Apache-2.0
