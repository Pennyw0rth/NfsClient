# pyNfsClient

- [pyNfsClient](#pynfsclient)
  - [Introduction](#introduction)
  - [Installation](#installation)
  - [Example](#example)
  - [Authentication](#authentication)

## Introduction

pyNfsClient is an open source Python library for interacting with NFS servers.
It provides separate NFSv3 and NFSv4.0 implementations and allows applications
to construct custom workflows from protocol operations.

pyNfsClient is operating system and application independent. The toolkit is
implemented using [Python](https://www.python.org) and requires Python 3.10 or
newer.

The pyNfsClient project is hosted on [GitHub](https://github.com/Pennyw0rth/NfsClient),
where you can find source code, an issue tracker, and further documentation.

[![Latest version](https://img.shields.io/pypi/v/pyNfsClient.svg?label=version)](https://pypi.org/project/pyNfsClient/)

## Installation

If you already have [Python](https://www.python.org) with
[pip](https://pip.pypa.io/) installed, run:

```console
pip install pyNfsClient
```

Alternatively, download the source distribution from
[PyPI](https://pypi.org/project/pyNfsClient/) and extract it, or clone the
project repository from [GitHub](https://github.com/Pennyw0rth/NfsClient).
Then install the framework with:

```console
python -m pip install .
```

NFSv4 connects directly to TCP port 2049 and does not use rpcbind or the MOUNT
protocol. NFSv3 continues to discover its services through rpcbind.

## Example

The raw NFSv4 client connects directly to the NFS service and never queries
rpcbind or MOUNT:

```python
from pyNfsClient import NFSv4

auth = {
    "flavor": 1,
    "machine_name": "client.example",
    "uid": 1000,
    "gid": 1000,
    "aux_gid": [10, 20],
}
client = NFSv4("nfs.example", auth=auth)
client.connect()
try:
    root = client.root_filehandle()
    print(client.readdirplus(root))
finally:
    client.disconnect()
```

NFSv3 uses `Portmap` and `Mount` to discover and mount an export before
constructing `NFSv3`. Both raw versions expose matching methods and response
dictionaries for their common filesystem operations. No version-selecting
client facade is provided.

NFSv4 wire-operation builders use names such as `lookup_op` and `read_op`.
They can be combined through `compound` when an application needs direct
access to NFSv4-only state, locking, or sequencing behavior.

## Authentication

Raw RPC calls accept AUTH_NONE as `None` and AUTH_SYS as a credential
dictionary, as shown above.

For Kerberos, establish the selected RPCSEC_GSS service on the raw connection:

```python
from pyNfsClient import NFSv4
from pyNfsClient.kerberos import KerberosInitiator
from pyNfsClient.nfs4_const import NFS_PROGRAM, NFS_V4
from pyNfsClient.rpcsec_gss import RPCSECGSSAuth

client = NFSv4("192.0.2.10")
client.connect()
client.auth = RPCSECGSSAuth.establish(
    client,
    NFS_PROGRAM,
    NFS_V4,
    KerberosInitiator("192.0.2.10", {
        "realm": "EXAMPLE.TEST",
        "username": "nfsclient",
        "ccache": "/path/to/krb5cc",
        "hostname": "nfs.example.test",
        "kdc_host": "192.0.2.20",
    }),
    "krb5p",
)
```

Password, LM/NT hash, AES key, keytab, credential cache, supplied TGT, and
supplied TGS sources are supported. Kerberos is an optional dependency; use
`python -m pip install '.[kerberos]'`. The current RPCSEC_GSS implementation
also needs the companion Impacket changes from this development work until
they are available in a public Impacket release.
