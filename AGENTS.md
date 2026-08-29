# Project guidance

## Development target

- Use `192.168.108.140` as the authorized NFS development and integration-test target.
- NFSv4 connects directly to TCP port 2049. It must not require rpcbind, the MOUNT protocol, or TCP/UDP port 111.
- Keep the NFSv3 rpcbind and MOUNT workflow separate from the NFSv4 workflow.
- Do not store target credentials, Kerberos keys, keytabs, or credential-cache contents in this repository.

## Implementation

- Keep code short, well structured, and consistent with the conventions already established in this library.
- Keep NFSv3 and NFSv4 implementations separate, with shared behavior factored only where it is genuinely version independent.
- Give the raw `NFSv3` and `NFSv4` classes the same names, signatures, authentication overrides, and NFSv3-shaped response dictionaries for operations common to both protocol versions.
- Name NFSv4 wire-operation builders with an `_op` suffix so the ordinary operation names execute requests just as they do on `NFSv3`.
- Do not add or expose an `NFSClient` facade or a top-level version-selecting client.
- NetExec must import and use raw `NFSv3` and `NFSv4` objects directly from its NFS protocol. Do not add an `NFSClient`, `NFSProtocolClient`, or equivalent adapter there.
- NetExec defaults to NFSv3 so rpcbind can enumerate advertised versions and exports. NFSv4 remains an explicit mode that connects directly to TCP port 2049 without using port 111.
- Keep NetExec version branches limited to connection setup, authentication/state initialization, root/export discovery, and teardown. Filesystem operations and root escape must use the same raw calls for both versions.
- Make the smallest changes needed in third-party projects, including Impacket and NetExec, and integrate them with their existing public interfaces and conventions.
- Preserve compatibility unless a change is explicitly required by the task.
- Keep library code and paths cross-platform. Target-specific integration tests may explicitly depend on the authorized Debian host.
- If you are unsure about anything, ask for clarification before proceeding.

## Coding style

- Keep function and method call arguments on one line when practical, including in existing files; only wrap them when a single line would materially hurt readability. This applies to calls, not object literals such as dictionaries, lists, tuples, or sets, which should be formatted for readability.
- Only assign an expression to a variable when that variable will be reassigned later; otherwise, use the expression directly.
- Always bind caught exceptions as `e`, not `error` or another name.
- Do not prefix function or method names with underscores; preserve required Python special methods such as `__init__`.
