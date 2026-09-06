import inspect
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pyNfsClient import nfs4_const as const
from pyNfsClient import nfs4_types as types
from pyNfsClient import nfs41_const as const41
from pyNfsClient.client import NFSClient, OpenFile
from pyNfsClient.nfs3 import NFSv3
from pyNfsClient.nfs40 import NFSv40
from pyNfsClient.nfs41 import NFSv41
from pyNfsClient.nfs42 import NFSv42
from pyNfsClient.nfs4_base import NFS4Error


COMMON_METHODS = (
    "null", "getattr", "setattr", "lookup", "access", "readlink", "read", "write",
    "create", "mkdir", "symlink", "mknod", "remove", "rmdir", "rename", "link",
    "readdir", "readdirplus", "fsstat", "fsinfo", "pathconf", "commit",
)


def auth(uid=0, gid=0):
    return {"flavor": 1, "machine_name": "client", "uid": uid, "gid": gid, "aux_gid": []}


def compound(*results):
    return types.Compound4Res(const.NFS4_OK, b"", results)


@pytest.mark.parametrize(("version", "raw_type"), [("4.0", NFSv40), ("4.1", NFSv41), ("4.2", NFSv42)])
def test_constructor_selects_exact_raw_v4_client(version, raw_type):
    client = NFSClient("server", version)
    assert isinstance(client.raw, raw_type)
    assert client.port == 2049


def test_constructor_rejects_unknown_versions_and_v3_identity():
    with pytest.raises(ValueError):
        NFSClient("server", "4")
    with pytest.raises(ValueError):
        NFSClient("server", "3", client_identity=object())


def test_standard_method_signatures_match_nfsv3():
    for name in COMMON_METHODS:
        assert inspect.signature(getattr(NFSClient, name)) == inspect.signature(getattr(NFSv3, name))


def test_v3_lifecycle_discovers_ports_and_delegates_calls():
    events = []

    class FakePortmap:
        def __init__(self, host, timeout, port):
            assert (host, timeout, port) == ("server", 7, 111)
            self.client = None

        def connect(self):
            self.client = object()
            events.append("portmap-connect")

        @staticmethod
        def getport(program, version):
            return 2049 if program == 100003 else 20048

        def disconnect(self):
            events.append("portmap-disconnect")

    class FakeMount:
        program = 100005
        program_version = 3

        def __init__(self, host, port, timeout, mount_auth):
            assert (host, port, timeout, mount_auth["uid"]) == ("server", 20048, 7, 10)
            self.client = None

        def connect(self):
            self.client = object()
            events.append("mount-connect")

        def disconnect(self):
            events.append("mount-disconnect")

    class FakeNFS:
        def __init__(self, host, port, timeout, call_auth):
            assert (host, port, timeout, call_auth["uid"]) == ("server", 2049, 7, 10)
            self.client = None
            self.auth = call_auth

        def connect(self):
            self.client = object()
            events.append("nfs-connect")

        @staticmethod
        def lookup(dir_handle, name, auth=None):
            return {"status": 0, "arguments": (dir_handle, name, auth)}

        def disconnect(self):
            events.append("nfs-disconnect")

    with patch("pyNfsClient.client.Portmap", FakePortmap), patch("pyNfsClient.client.Mount", FakeMount), patch("pyNfsClient.client.NFSv3", FakeNFS):
        client = NFSClient("server", "3", timeout=7, auth=auth(10, 20)).connect()
        call_auth = auth(30, 40)
        assert client.lookup(b"root", "name", auth=call_auth)["arguments"] == (b"root", "name", call_auth)
        assert client.port == 2049
        client.disconnect()
    assert events == ["portmap-connect", "nfs-connect", "mount-connect", "nfs-disconnect", "mount-disconnect", "portmap-disconnect"]


def test_v3_partial_connection_failure_rolls_back_open_transports():
    events = []

    class FakePortmap:
        def __init__(self, *args, **kwargs):
            self.client = None

        def connect(self):
            self.client = object()

        @staticmethod
        def getport(program, version):
            return 2049 if program == 100003 else 20048

        def disconnect(self):
            events.append("portmap-disconnect")

    class FakeRPC:
        program = 100005
        program_version = 3

        def __init__(self, *args, **kwargs):
            self.client = None

        def connect(self):
            self.client = object()
            if isinstance(self, FakeMount):
                raise ConnectionError("MOUNT failed")

        def disconnect(self):
            events.append("mount-disconnect" if isinstance(self, FakeMount) else "nfs-disconnect")

    class FakeMount(FakeRPC):
        pass

    with patch("pyNfsClient.client.Portmap", FakePortmap), patch("pyNfsClient.client.Mount", FakeMount), patch("pyNfsClient.client.NFSv3", FakeRPC):
        client = NFSClient("server", "3")
        with pytest.raises(ConnectionError, match="MOUNT failed"):
            client.connect()
    assert events == ["mount-disconnect", "nfs-disconnect", "portmap-disconnect"]
    assert (client.raw, client.mount, client.portmap, client.port) == (None, None, None, None)


def test_explicit_v3_data_port_still_discovers_mount_through_rpcbind():
    class FakePortmap:
        def __init__(self, *args, **kwargs):
            self.client = None

        def connect(self):
            self.client = object()

        @staticmethod
        def getport(program, version):
            assert program != 100003
            return 20048

        def disconnect(self):
            pass

    class FakeRPC:
        program = 100005
        program_version = 3

        def __init__(self, host, port, timeout, call_auth=None):
            self.port = port
            self.client = None
            self.auth = call_auth

        def connect(self):
            self.client = object()

        def disconnect(self):
            pass

    with patch("pyNfsClient.client.Portmap", FakePortmap), patch("pyNfsClient.client.Mount", FakeRPC), patch("pyNfsClient.client.NFSv3", FakeRPC):
        client = NFSClient("server", "3", port=3049).connect()
        assert client.raw.port == 3049
        assert client.mount.port == 20048
        client.disconnect()


def test_set_auth_changes_raw_auth_but_preserves_mount_auth():
    initial = auth(1, 2)
    replacement = object()
    client = NFSClient("server", "3", auth=initial)
    client.raw = SimpleNamespace(auth=initial)
    assert client.set_auth(replacement) is replacement
    assert client.raw.auth is replacement
    assert client.mount_auth is initial


def test_v4_getattr_uses_nfsv3_attribute_shape():
    client = NFSClient("server", "4.2")
    attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4REG, const.FATTR4_MODE: 0o640, const.FATTR4_OWNER: "1000", const.FATTR4_OWNER_GROUP: "users", const.FATTR4_SIZE: 4})
    client.get_attributes4 = lambda *args, **kwargs: (const.NFS4_OK, attributes)
    result = client.getattr(b"file")
    assert result["attributes"]["uid"] == 1000
    assert result["attributes"]["gid"] == "users"
    assert result["attributes"]["mode"] == 0o640


def test_v41_existing_file_open_uses_claim_fh_and_tracks_principal():
    call_auth = auth(1000, 1000)
    client = NFSClient("server", "4.1", auth=call_auth)
    raw = client.raw
    raw.clientid = 9
    raw.sessionid = b"s" * const41.NFS4_SESSIONID_SIZE
    captured = []
    stateid = types.Stateid4(1, b"state-id-001")
    result = types.Open4Res(stateid, types.ChangeInfo4(True, 1, 2), 0, types.Bitmap4(), types.OpenDelegation4())

    def send(operations, tag=b"", auth=None, check=True):
        captured.append((operations, auth))
        return compound(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN, const.NFS4_OK, result), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"file"))

    raw.compound = send
    opened = client.open_existing(b"file", const.OPEN4_SHARE_ACCESS_WRITE, call_auth)
    assert captured[0][0][1].arg.claim.claim == const41.CLAIM_FH
    assert captured[0][0][1].arg.share_access & const41.OPEN4_SHARE_ACCESS_WANT_NO_DELEG
    assert opened.stateid == stateid
    assert client.state_key(b"file", call_auth, const.OPEN4_SHARE_ACCESS_WRITE, const.OPEN4_SHARE_DENY_NONE) in client.opened


def test_delegation_return_failure_retains_open_state_for_cleanup():
    call_auth = auth(1000, 1000)
    client = NFSClient("server", "4.1", auth=call_auth)
    client.raw.clientid = 9
    client.raw.sessionid = b"s" * const41.NFS4_SESSIONID_SIZE
    stateid = types.Stateid4(1, b"state-id-001")
    result = types.Open4Res(stateid, types.ChangeInfo4(True, 1, 2), 0, types.Bitmap4(), types.OpenDelegation4())
    client.raw.compound = lambda *args, **kwargs: compound(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN, const.NFS4_OK, result), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"file"))
    client.return_delegation = lambda *args: (_ for _ in ()).throw(RuntimeError("DELEGRETURN failed"))

    with pytest.raises(RuntimeError, match="DELEGRETURN failed"):
        client.open_existing(b"file", const.OPEN4_SHARE_ACCESS_READ, call_auth)
    assert client.find_open(b"file", call_auth, const.OPEN4_SHARE_ACCESS_READ)[1].stateid == stateid


def test_v40_reopen_rejects_replaced_path_identity():
    call_auth = auth(1000, 1000)
    client = NFSClient("server", "4.0", auth=call_auth)
    client.raw.clientid = 9
    client.locations[b"original"] = (b"parent", b"name")
    prepared = SimpleNamespace(state=SimpleNamespace(stateid=types.Stateid4()))
    calls = []
    client.raw.prepare_open = lambda *args, **kwargs: prepared
    client.raw.prepare_close = lambda *args, **kwargs: "close-operation"

    def send(operations, tag=b"", auth=None, check=True):
        calls.append((operations, tag))
        if tag == b"open":
            return compound(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN, const.NFS4_OK), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"replacement"))
        return compound()

    client.raw.compound = send
    opened = client.open_existing(b"original", const.OPEN4_SHARE_ACCESS_READ, call_auth)
    assert opened.filehandle == b"original"
    assert opened.stateid == types.Stateid4()
    assert b"original" not in client.locations
    assert calls[-1][1] == b"close-replacement"


def test_cached_open_state_is_not_reused_for_another_auth_principal():
    first = auth(1000, 100)
    second = auth(2000, 200)
    client = NFSClient("server", "4.1", auth=first)
    client.raw.clientid = 7
    opened = OpenFile(b"file", types.Stateid4(), const.OPEN4_SHARE_ACCESS_WRITE, const.OPEN4_SHARE_DENY_NONE, client.principal(first), client.auth_snapshot(first))
    client.opened[client.state_key(b"file", first, opened.share_access, opened.share_deny)] = opened
    client.close_opened = lambda value: const.NFS4_OK
    assert client.close(b"file", second)["status"] == const.NFS4_OK
    assert len(client.opened) == 1
    assert client.close(b"file", first)["status"] == const.NFS4_OK
    assert not client.opened


def test_mutating_auth_sys_does_not_reuse_the_saved_open_principal():
    mutable_auth = auth(1000, 100)
    client = NFSClient("server", "4.1", auth=mutable_auth)
    client.raw.clientid = 7
    saved_auth = client.auth_snapshot(mutable_auth)
    opened = OpenFile(b"file", types.Stateid4(), const.OPEN4_SHARE_ACCESS_WRITE, const.OPEN4_SHARE_DENY_NONE, client.principal(saved_auth), saved_auth)
    client.opened[client.state_key(b"file", saved_auth, opened.share_access, opened.share_deny)] = opened
    client.close_opened = lambda value: const.NFS4_OK
    mutable_auth.update(uid=2000, gid=200)
    assert client.close(b"file", mutable_auth)["status"] == const.NFS4_OK
    assert len(client.opened) == 1
    assert client.close(b"file", saved_auth)["status"] == const.NFS4_OK
    assert not client.opened


def test_disconnect_orders_state_session_gss_and_transport_teardown():
    events = []
    client = NFSClient("server", "4.1")

    class Raw:
        client = object()

        @staticmethod
        def destroy_session():
            events.append("destroy-session")

        @staticmethod
        def destroy_client():
            events.append("destroy-client")

        @staticmethod
        def disconnect():
            events.append("disconnect")

    class GSS:
        @staticmethod
        def destroy(rpc, program, version):
            events.append("destroy-gss")

    client.raw = Raw()
    client.gss_auth = GSS()
    client.opened[(1,)] = OpenFile(b"file", types.Stateid4(), 1, 0, None, None)
    client.close_opened = lambda opened: events.append("close-state") or const.NFS4_OK
    client.disconnect()
    assert events == ["close-state", "destroy-session", "destroy-client", "destroy-gss", "disconnect"]


def test_close_failure_retains_state_and_disconnect_still_attempts_all_teardown():
    events = []
    failure = RuntimeError("DESTROY_SESSION failed")
    client = NFSClient("server", "4.1")

    class Raw:
        client = object()
        clientid = 7

        @staticmethod
        def auth_identity(auth):
            return id(auth)

        @staticmethod
        def destroy_session():
            events.append("destroy-session")
            raise failure

        @staticmethod
        def destroy_client():
            events.append("destroy-client")

        @staticmethod
        def disconnect():
            events.append("disconnect")

    class GSS:
        @staticmethod
        def destroy(rpc, program, version):
            events.append("destroy-gss")

    client.raw = Raw()
    client.gss_auth = GSS()
    opened = OpenFile(b"file", types.Stateid4(), const.OPEN4_SHARE_ACCESS_WRITE, const.OPEN4_SHARE_DENY_NONE, client.principal(None), None)
    key = client.state_key(b"file", None, opened.share_access, opened.share_deny)
    client.opened[key] = opened
    client.close_opened = lambda value: const.NFS4ERR_DELAY
    assert client.close(b"file")["status"] == const.NFS4ERR_DELAY
    assert key in client.opened
    with pytest.raises(NFS4Error) as caught:
        client.disconnect()
    assert caught.value.status == const.NFS4ERR_DELAY
    assert events == ["destroy-session", "destroy-client", "destroy-gss", "disconnect"]


def test_gss_establishment_is_lazy_and_updates_raw_auth():
    client = NFSClient("server", "4.0")
    client.raw.client = object()
    established = object()
    with patch("pyNfsClient.rpcsec_gss.RPCSECGSSAuth.establish", return_value=established) as establish:
        assert client.establish_gss("initiator", "krb5p") is established
    establish.assert_called_once_with(client.raw, 100003, 4, "initiator", "krb5p")
    assert client.raw.auth is established


def test_root_handle_walks_v4_pseudofilesystem_without_mount():
    client = NFSClient("server", "4.2")
    client.raw.compound = lambda *args, **kwargs: compound(types.ResOp4(const.OP_PUTROOTFH, const.NFS4_OK), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"root"))
    handles = iter((b"export", b"child"))
    client.lookup = lambda handle, name, auth=None: {"status": 0, "resok": {"object": {"data": next(handles)}}}
    assert client.root_handle("/export/child")["mountinfo"]["fhandle"] == b"child"
    assert client.mount is None


def test_v4_null_matches_nfsv3_response_shape():
    client = NFSClient("server", "4.2")
    client.raw.null = lambda: None
    assert client.null() == {"status": const.NFS4_OK, "resok": None}
