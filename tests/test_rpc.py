import struct
from unittest.mock import Mock

import pytest

from pyNfsClient.rpc import RPC, RPCAcceptError, RPCAuthenticationError, RPCProtocolError
from pyNfsClient.rpc_const import AUTH_NONE, MSG_ACCEPTED, PROG_MISMATCH, PROG_UNAVAIL, REPLY, SUCCESS


class FragmentedSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = b""

    def recv(self, size):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        self.chunks.insert(0, chunk[size:]) if len(chunk) > size else None
        return chunk[:size]

    def sendall(self, data):
        self.sent += data


class RetryingSocket:
    def __init__(self, reply):
        self.reply = bytearray(reply)
        self.sent = []
        self.timed_out = False

    def recv(self, size):
        if not self.timed_out:
            self.timed_out = True
            raise TimeoutError
        data = bytes(self.reply[:size])
        del self.reply[:size]
        return data

    def sendall(self, data):
        self.sent.append(data)


def split_bytes(data):
    return [data[:1], data[1:3], data[3:7], data[7:11], data[11:]]


def accepted_reply(xid, payload=b"", verifier=b""):
    body = struct.pack("!3L", xid, REPLY, MSG_ACCEPTED)
    body += RPC.pack_opaque_auth(AUTH_NONE, verifier)
    body += struct.pack("!L", SUCCESS) + payload
    return struct.pack("!L", 0x80000000 | len(body)) + body


def test_connect_always_binds_a_privileged_source_port(monkeypatch):
    client = Mock()
    monkeypatch.setattr("pyNfsClient.rpc.socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("server", 2049))])
    monkeypatch.setattr("pyNfsClient.rpc.socket.socket", lambda *args: client)

    rpc = RPC("server", 2049, 1)
    rpc.connect()

    client.bind.assert_called_once_with(("", 1))
    client.connect.assert_called_once_with(("server", 2049))
    rpc.disconnect()


def test_connect_tries_privileged_ports_in_order(monkeypatch):
    client = Mock()
    client.bind.side_effect = [OSError("address in use"), None]
    monkeypatch.setattr("pyNfsClient.rpc.socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("server", 2049))])
    monkeypatch.setattr("pyNfsClient.rpc.socket.socket", lambda *args: client)

    rpc = RPC("server", 2049, 1)
    rpc.connect()

    assert [call.args[0] for call in client.bind.call_args_list] == [("", 1), ("", 2)]
    assert rpc.client_port == 2
    rpc.disconnect()


def test_connect_reports_privileged_bind_permission_failure(monkeypatch):
    client = Mock()
    client.bind.side_effect = PermissionError(13, "permission denied")
    monkeypatch.setattr("pyNfsClient.rpc.socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("server", 2049))])
    monkeypatch.setattr("pyNfsClient.rpc.socket.socket", lambda *args: client)

    with pytest.raises(RPCProtocolError, match="requires permission"):
        RPC("server", 2049, 1).connect()

    client.connect.assert_not_called()


def test_request_handles_partial_tcp_reads_and_variable_verifier(monkeypatch):
    monkeypatch.setattr("pyNfsClient.rpc.secrets.randbits", lambda bits: 0x12345678)
    rpc = RPC("server", 2049, 1)
    rpc.client = FragmentedSocket(split_bytes(accepted_reply(0x12345678, b"result", b"mic")))

    assert rpc.request(100003, 4, 1, b"args") == b"result"
    assert struct.unpack("!L", rpc.client.sent[:4])[0] == 0x80000000 | (len(rpc.client.sent) - 4)


@pytest.mark.parametrize(
    "auth",
    [
        None,
        {
            "flavor": 1,
            "machine_name": "client",
            "uid": 1000,
            "gid": 1000,
            "aux_gid": [],
        },
    ],
)
def test_prepared_plain_request_reuses_exact_bytes(monkeypatch, auth):
    monkeypatch.setattr("pyNfsClient.rpc.secrets.randbits", lambda bits: 0x12345678)
    rpc = RPC("server", 2049, 1)
    rpc.client = RetryingSocket(accepted_reply(0x12345678, b"result"))
    prepared = rpc.prepare_request(100003, 4, 1, b"arguments", auth=auth)

    with pytest.raises(TimeoutError):
        rpc.send_prepared(prepared)

    assert rpc.retransmit(prepared) == b"result"
    assert rpc.client.sent[0] == rpc.client.sent[1]
    assert prepared.body == b"arguments"


def test_recv_record_reassembles_multiple_fragments():
    first = struct.pack("!L", 3) + b"abc"
    second = struct.pack("!L", 0x80000002) + b"de"
    rpc = RPC("server", 2049, 1)
    rpc.client = FragmentedSocket(split_bytes(first + second))

    assert rpc.recv_record() == b"abcde"


def test_request_rejects_mismatched_xid(monkeypatch):
    monkeypatch.setattr("pyNfsClient.rpc.secrets.randbits", lambda bits: 7)
    rpc = RPC("server", 2049, 1)
    rpc.client = FragmentedSocket([accepted_reply(8)])

    with pytest.raises(RPCProtocolError, match="does not match"):
        rpc.request(100003, 4, 1)


def test_auth_sys_credential_encodes_zero_auxiliary_groups():
    credential = RPC.pack_credential(
        {
            "flavor": 1,
            "machine_name": "client",
            "uid": 1000,
            "gid": 1000,
            "aux_gid": [],
        }
    )

    assert struct.unpack("!L", credential[:4])[0] == 1
    assert struct.unpack("!L", credential[-4:])[0] == 0


def test_recv_exact_reports_early_close():
    rpc = RPC("server", 2049, 1)
    rpc.client = FragmentedSocket([b"ab"])

    with pytest.raises(RPCProtocolError, match="2 bytes left"):
        rpc.recv_exact(4)


def test_authentication_error_preserves_legacy_message():
    assert str(RPCAuthenticationError(2)) == "RPC_AUTH_ERROR: AUTH_REJECTEDCRED"


def test_accepted_program_errors_preserve_status_and_version_range():
    with pytest.raises(RPCAcceptError) as unavailable:
        RPC.raise_accept_error(PROG_UNAVAIL, b"")
    assert unavailable.value.status == PROG_UNAVAIL
    assert str(unavailable.value) == "RPC program is unavailable"

    with pytest.raises(RPCAcceptError) as mismatch:
        RPC.raise_accept_error(PROG_MISMATCH, struct.pack("!2L", 3, 4))
    assert (mismatch.value.status, mismatch.value.low, mismatch.value.high) == (PROG_MISMATCH, 3, 4)
    assert str(mismatch.value) == "RPC program version mismatch; server supports 3 through 4"
