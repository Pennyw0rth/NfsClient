# Project guidance

## Development target

- Use `192.168.108.140` as the authorized NFS development and integration-test target.
- NFSv4 connects directly to TCP port 2049. It must not require rpcbind, the MOUNT protocol, or TCP/UDP port 111.
- RPC transports always bind to a privileged source port; do not expose an option to disable privileged-port binding.
- Keep the NFSv3 rpcbind and MOUNT workflow separate from the NFSv4 workflow.
- Do not store target credentials, Kerberos keys, keytabs, or credential-cache contents in this repository.

## Implementation

- Keep code short, well structured, and consistent with the conventions already established in this library.
- Keep NFSv3 and NFSv4 implementations separate, with shared behavior factored only where it is genuinely version independent.
- Expose NFSv4.0, NFSv4.1, and NFSv4.2 explicitly as `NFSv40`, `NFSv41`, and `NFSv42`; do not export a legacy `NFSv4` alias.
- Expose RFC wire-operation builders with an `_op` suffix and execute caller-assembled operations through raw `compound` calls.
- Expose `NFSClient` as the version-explicit generic filesystem client while preserving the raw protocol clients for direct RFC operations. It must not silently select or negotiate a version.
- Give `NFSClient` the NFSv3 method signatures and response dictionaries for common filesystem operations, and keep NFSv4 state IDs and COMPOUND construction internal to it.
- NetExec must use `NFSClient` for filesystem and lifecycle operations. Keep version-specific logic there limited to discovery and selecting the exact client version.
- NetExec automatically prefers NFSv3 when it is advertised and otherwise selects the latest discovered NFSv4 minor version. Exact values `3`, `4.0`, `4.1`, and `4.2` remain available; do not accept a legacy `4` value.
- Keep NFSv4 clients usable by one-shot processes. Do not require a daemon, callback listener, persistent CLI, or cross-process state service; advertise no callback/backchannel functionality and do not retain delegations.
- Make the smallest changes needed in third-party projects, including Impacket and NetExec, and integrate them with their existing public interfaces and conventions.
- Preserve compatibility unless a change is explicitly required by the task.
- Keep library code and paths cross-platform. Target-specific integration tests may explicitly depend on the authorized Debian host.
- If you are unsure about anything, ask for clarification before proceeding.

## Coding style

- Never add a comment or docstring at the top of a Python file unless that file already has a top-of-file comment or docstring.
- In parenthesized Python import blocks, group multiple imported names on each line instead of placing every name on its own line; for example, divide 15 imports across roughly three readable lines.
- Keep function and method call arguments on one line when practical, including in existing files; only wrap them when a single line would materially hurt readability. This applies to calls, not object literals such as dictionaries, lists, tuples, or sets, which should be formatted for readability.
- Keep comments short and precise; longer single lines are preferable to splitting one comment across several lines. Keep docstrings and other long text in block form.
- Only assign an expression to a variable when that variable will be reassigned later; otherwise, use the expression directly.
- Exception handlers do not need to bind the exception; when one is bound, name it `e`, not `error` or another name.
- Do not prefix function or method names with underscores; preserve required Python special methods such as `__init__`.
