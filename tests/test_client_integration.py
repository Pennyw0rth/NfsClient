import os
import uuid

import pytest

from pyNfsClient import FILE_SYNC, GUARDED, NFSClient


LIVE = os.getenv("PYNFSCLIENT_GENERIC_INTEGRATION") == "1"


def integration_auth():
    return {
        "flavor": 1,
        "machine_name": "pynfsclient-generic-integration",
        "uid": int(os.getenv("PYNFSCLIENT_NFS_UID", "65534")),
        "gid": int(os.getenv("PYNFSCLIENT_NFS_GID", "65534")),
        "aux_gid": [],
    }


def integration_root(client, version, auth):
    if version != "3":
        return client.root_handle(os.getenv("PYNFSCLIENT_NFS4_EXPORT", "/pynfsclient"), auth)["mountinfo"]["fhandle"]
    mounted = client.root_handle(os.getenv("PYNFSCLIENT_NFS3_EXPORT", "/var/nfs"), auth)["mountinfo"]["fhandle"]
    directory = os.getenv("PYNFSCLIENT_NFS3_DIRECTORY", "pynfsclient")
    return mounted if not directory else client.lookup(mounted, directory, auth)["resok"]["object"]["data"]


@pytest.mark.skipif(not LIVE, reason="set PYNFSCLIENT_GENERIC_INTEGRATION=1 to run generic NFS integration tests")
@pytest.mark.parametrize("version", ("3", "4.0", "4.1", "4.2"))
def test_generic_filesystem_workflow(version):
    auth = integration_auth()
    client = NFSClient(os.getenv("PYNFSCLIENT_NFS_HOST", "192.168.108.140"), version, timeout=int(os.getenv("PYNFSCLIENT_NFS_TIMEOUT", "10")), auth=auth)
    directory_name = f"generic-{version.replace('.', '')}-{uuid.uuid4().hex}".encode()
    root = directory = filehandle = None
    client.connect()
    try:
        root = integration_root(client, version, auth)
        assert client.getattr(root, auth=auth)["status"] == 0
        assert client.readdirplus(root, auth=auth)["status"] == 0

        result = client.mkdir(root, directory_name, mode=0o700, auth=auth)
        assert result["status"] == 0
        directory = result["resok"]["obj"]["handle"]["data"]

        result = client.create(directory, b"original", GUARDED, mode=0o600, auth=auth)
        assert result["status"] == 0
        filehandle = result["resok"]["obj"]["handle"]["data"]
        payload = b"generic NFS client integration payload"
        result = client.write(filehandle, 0, len(payload), payload, FILE_SYNC, auth=auth)
        assert result["status"] == 0
        assert result["resok"]["count"] == len(payload)
        result = client.read(filehandle, 0, len(payload), auth=auth)
        assert result["status"] == 0
        assert result["resok"]["data"] == payload
        assert client.setattr(filehandle, mode=0o640, auth=auth)["status"] == 0
        assert client.close(filehandle, auth=auth)["status"] == 0

        assert client.rename(directory, b"original", directory, b"renamed", auth=auth)["status"] == 0
        assert client.lookup(directory, b"renamed", auth=auth)["resok"]["object"]["data"] == filehandle
        assert client.remove(directory, b"renamed", auth=auth)["status"] == 0
        filehandle = None
        assert client.rmdir(root, directory_name, auth=auth)["status"] == 0
        directory = None
    finally:
        if filehandle is not None and directory is not None:
            client.close(filehandle, auth=auth)
            client.remove(directory, b"original", auth=auth)
            client.remove(directory, b"renamed", auth=auth)
        if directory is not None and root is not None:
            client.rmdir(root, directory_name, auth=auth)
        client.disconnect()
    assert client.raw.client is None
