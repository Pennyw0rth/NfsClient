# pyNfsClient

pyNfsClient is a pure-Python ONC RPC and NFS toolkit. It provides one generic
filesystem client and explicit raw clients for NFSv3 and the three NFSv4 minor
versions used by this project.

The project is hosted on [GitHub](https://github.com/Pennyw0rth/NfsClient),
with releases published on [PyPI](https://pypi.org/project/pyNfsClient/).

[![Latest version](https://img.shields.io/pypi/v/pyNfsClient.svg?label=version)](https://pypi.org/project/pyNfsClient/)

Python 3.10 or newer is required.

## Installation

Install the published release with:

```console
python -m pip install pyNfsClient
```

To install the current source checkout instead, run:

```console
python -m pip install .
```

Kerberos and RPCSEC_GSS support use Impacket and remain optional:

```console
python -m pip install '.[kerberos]'
```

Importing `pyNfsClient`, using AUTH_NONE, or using AUTH_SYS does not import
Impacket.

## Protocol clients

| Public class | Protocol | Initialization |
| --- | --- | --- |
| `NFSClient` | Exact version selected by the caller | Owns transport, state, and common filesystem operations |
| `NFSv3` | NFSv3 | Existing rpcbind and MOUNT workflow |
| `NFSv40` | NFSv4.0 | `SETCLIENTID` only when state is needed |
| `NFSv41` | NFSv4.1 | `EXCHANGE_ID`, `CREATE_SESSION`, and `SEQUENCE` |
| `NFSv42` | NFSv4.2 | The NFSv4.1 session engine with minor version 2 |

There is no `NFSv4` alias. `NFSClient` accepts the exact version strings `3`,
`4.0`, `4.1`, and `4.2`; it does not silently negotiate or fall back. NFSv4
connects directly to TCP port 2049 and never depends on rpcbind, MOUNT, or port
111.

ONC RPC messages still use RPC protocol version 2. “NFS version 4” means
program 100003, program version 4; the COMPOUND `minorversion` field selects
NFSv4.0, NFSv4.1, or NFSv4.2.

## Generic filesystem client

The generic client exposes NFSv3-shaped methods and response dictionaries for
common operations such as `lookup`, `getattr`, `readdirplus`, `read`, `write`,
`create`, `mkdir`, `rename`, and `remove`:

```python
from pyNfsClient import NFSClient

with NFSClient("nfs.example", "4.1") as client:
    root = client.root_handle("/")["mountinfo"]["fhandle"]
    entries = client.readdirplus(root)
```

The raw clients remain available when an application needs to build RFC
operations directly. The generic client keeps NFSv4 OPEN state, sequence IDs,
sessions, and response conversion internal.

## Version probing

Probing sends a state-free `PUTROOTFH` COMPOUND and does not create a client ID
or session:

```python
from pyNfsClient import discover_nfs_versions, probe_minor_version

print(probe_minor_version("nfs.example", 1))
print(discover_nfs_versions("nfs.example").supported)
```

Full discovery checks rpcbind for a dynamic NFSv3 endpoint, then probes the
direct NFS endpoint for NFSv3 and minor versions 2, 1, and 0 independently. Its
result separates supported versions from inconclusive authentication,
transport, timeout, and malformed-reply failures. Probing creates no NFSv4
client ID or session.

## Raw COMPOUND use

Applications using a raw client assemble filesystem operations themselves:

```python
from pyNfsClient import NFSv41
from pyNfsClient.nfs4_const import OP_GETFH

client = NFSv41("nfs.example")
client.connect()
try:
    response = client.compound((client.putrootfh_op(), client.getfh_op()), tag=b"root")
    root_filehandle = client.operation_result(response, OP_GETFH)
finally:
    client.disconnect()
```

`NFSv41` and `NFSv42` add the mandatory `SEQUENCE` operation and manage one
serialized forechannel slot. The caller remains responsible for the remaining
operations and their order. `NFSv40` exposes principal-aware prepared
OPEN/CLOSE state in addition to the raw builders because NFSv4.0 state-owner
sequence IDs require exact replay.

`getattr_op()` and `readdir_op()` request no attributes by default. Attribute
values are not self-describing, so callers must first request
`FATTR4_SUPPORTED_ATTRS`, then intersect the returned bitmap with the exported
`DEFAULT_ATTRIBUTES` or `DIRECTORY_ATTRIBUTES` candidate mask before passing
it to either builder. This prevents an optional attribute from being decoded
before the server has confirmed support for it.

## One-shot operation and callbacks

None of the three clients requires a client-hosted service, daemon, or
persistent CLI for ordinary filesystem traffic.

- `NFSv40` advertises no usable callback program, and its prepared OPEN path
  immediately returns an unexpected delegation.
- `NFSv41` and `NFSv42` create a forechannel-only session with no backchannel,
  callback program, RDMA channel, or pNFS data path.
- `NFSv41` and `NFSv42` destroy sessions and client IDs during clean
  disconnect. `NFSv40` closes tracked OPEN state and lets its v4.0 client ID
  expire because v4.0 has no `DESTROY_CLIENTID` operation. A caller may provide
  `ClientIdentity` when stable identity across process invocations is required;
  no identity or replay state is persisted automatically.

This profile is designed for short-lived tools such as NetExec. Long-lived
callers must issue lease-renewing traffic and handle state recovery appropriate
to their workload.

## Authentication and state

Raw calls accept AUTH_NONE as `None` and AUTH_SYS as a dictionary:

```python
auth = {
    "flavor": 1,
    "machine_name": "client.example",
    "uid": 1000,
    "gid": 1000,
    "aux_gid": [10, 20],
}
```

Per-call authentication overrides are snapshotted before transmission. The
generic client partitions cached NFSv4 OPEN state by the effective principal
and never reuses a state ID under another identity. Raw callers must likewise
keep their state IDs associated with the principal that created them.

RPCSEC_GSS supports `krb5`, `krb5i`, and `krb5p`. See
[Kerberos setup](docs/kerberos.md) for the development-realm procedure and
[Impacket changes](docs/impacket.md) for the small interoperability patches
used by this development branch.

## Implemented profile

The shared raw layer implements the NFSv4.0 filesystem operations needed by a
one-shot client. NFSv4.1 removes the obsolete v4.0 initialization and renewal
operations and adds the mandatory session lifecycle. NFSv4.2 currently uses
that same session engine and common filesystem operation set.

Callbacks, retained delegations, backchannels, pNFS layouts, efficient
client-side caching, and optional NFSv4.2 operations such as COPY, CLONE, and
READ_PLUS are deliberately not implemented. The library does not claim those
capabilities merely because a server accepts minor version 2.

## Specifications

- NFSv4.0: [RFC 7530](https://www.rfc-editor.org/rfc/rfc7530) and
  [RFC 7531](https://www.rfc-editor.org/rfc/rfc7531)
- NFSv4.1: [RFC 8881](https://www.rfc-editor.org/rfc/rfc8881) and
  [RFC 5662](https://www.rfc-editor.org/rfc/rfc5662)
- NFSv4.2: [RFC 7862](https://www.rfc-editor.org/rfc/rfc7862) and
  [RFC 7863](https://www.rfc-editor.org/rfc/rfc7863)
- Minor-version rules: [RFC 8178](https://www.rfc-editor.org/rfc/rfc8178)
- RPCSEC_GSS: [RFC 2203](https://www.rfc-editor.org/rfc/rfc2203)

RFC 3530 is historical and is not the normative source for this implementation.
