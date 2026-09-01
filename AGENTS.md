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
- Do not add or expose an `NFSClient` facade or a top-level version-selecting client.
- NetExec must import the raw `NFSv3`, `NFSv40`, `NFSv41`, and `NFSv42` objects directly. Do not add an `NFSClient`, `NFSProtocolClient`, or equivalent adapter there.
- NetExec defaults to NFSv3 so rpcbind can enumerate advertised versions and exports. Exact versions `4.0`, `4.1`, and `4.2` are explicit modes that connect directly to TCP port 2049; do not accept a legacy `4` value.
- NetExec owns its NFSv4 COMPOUND construction. Keep version branches limited to lifecycle and version-specific state operations where possible.
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
