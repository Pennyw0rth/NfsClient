import struct

import pytest

from pyNfsClient.rpc import RPC
from pyNfsClient.rpc_const import MSG_ACCEPTED, REPLY, RPCSEC_GSS, SUCCESS
from pyNfsClient.rpcsec_gss import GSS_S_COMPLETE, RPC_GSS_SVC_INTEGRITY, RPC_GSS_SVC_PRIVACY, RPCSECGSSAuth, RPCSECGSSError, pack_opaque, unpack_opaque


class FakeContext:
    def __init__(self):
        self.verified = []

    @staticmethod
    def getMIC(data):
        return b"M" + data

    def verifyMIC(self, data, token):
        if token != b"M" + data:
            raise ValueError("bad MIC")
        self.verified.append(data)

    @staticmethod
    def wrap(data):
        return b"W" + data

    @staticmethod
    def unwrap(token):
        if not token.startswith(b"W"):
            raise ValueError("bad wrap token")
        return token[1:]


class FakeInitiator:
    def __init__(self):
        self.context = FakeContext()

    @staticmethod
    def start():
        return b"ap-req"

    @staticmethod
    def step(token):
        assert token == b"ap-rep"
        return None


class FakeRPC:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, program, version, procedure, data=None, auth=None):
        self.calls.append((program, version, procedure, data, auth))
        return RPCSEC_GSS, b"M" + struct.pack("!L", 32), self.response


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


def accepted_gss_reply(xid, verifier, payload):
    body = struct.pack("!3L", xid, REPLY, MSG_ACCEPTED)
    body += RPC.pack_opaque_auth(RPCSEC_GSS, verifier)
    body += struct.pack("!L", SUCCESS) + payload
    return struct.pack("!L", 0x80000000 | len(body)) + body


def test_establishes_context_and_checks_window_verifier():
    response = pack_opaque(b"server-handle")
    response += struct.pack("!3L", GSS_S_COMPLETE, 0, 32) + pack_opaque(b"ap-rep")
    rpc = FakeRPC(response)

    auth = RPCSECGSSAuth.establish(rpc, 100003, 4, FakeInitiator(), "krb5i")

    assert auth.handle == b"server-handle"
    assert auth.window == 32
    assert unpack_opaque(rpc.calls[0][3])[0] == b"ap-req"


def test_integrity_service_signs_header_and_body():
    context = FakeContext()
    auth = RPCSECGSSAuth(context, b"handle", "krb5i", sequence=7)
    call = auth.marshal_call(struct.pack("!6L", 1, 0, 2, 100003, 4, 1), b"arguments")

    assert auth.service == RPC_GSS_SVC_INTEGRITY
    assert b"arguments" in call
    cleartext = struct.pack("!L", 7) + b"result"
    reply = pack_opaque(cleartext) + pack_opaque(context.getMIC(cleartext))

    assert auth.process_reply(RPCSEC_GSS, context.getMIC(struct.pack("!L", 7)), reply) == b"result"
    assert auth.pending_sequence is None


def test_authentication_only_service_leaves_the_rpc_body_unwrapped():
    context = FakeContext()
    auth = RPCSECGSSAuth(context, b"handle", "krb5", sequence=5)
    call = auth.marshal_call(struct.pack("!6L", 1, 0, 2, 100003, 4, 1), b"arguments")

    assert call.endswith(b"arguments")
    assert auth.process_reply(RPCSEC_GSS, context.getMIC(struct.pack("!L", 5)), b"result") == b"result"


def test_privacy_service_wraps_and_unwraps_body():
    context = FakeContext()
    auth = RPCSECGSSAuth(context, b"handle", "krb5p", sequence=9)
    call = auth.marshal_call(struct.pack("!6L", 1, 0, 2, 100003, 4, 1), b"secret")

    assert auth.service == RPC_GSS_SVC_PRIVACY
    assert b"secret" in call
    reply = pack_opaque(context.wrap(struct.pack("!L", 9) + b"result"))

    assert auth.process_reply(RPCSEC_GSS, context.getMIC(struct.pack("!L", 9)), reply) == b"result"


@pytest.mark.parametrize("reply_sequence", [7, 8])
def test_prepared_gss_retry_keeps_xid_and_uses_fresh_sequence(monkeypatch, reply_sequence):
    monkeypatch.setattr("pyNfsClient.rpc.secrets.randbits", lambda bits: 0x12345678)
    context = FakeContext()
    auth = RPCSECGSSAuth(context, b"handle", "krb5i", sequence=7)
    cleartext = struct.pack("!L", reply_sequence) + b"result"
    rpc = RPC("server", 2049, 1)
    rpc.client = RetryingSocket(accepted_gss_reply(0x12345678, context.getMIC(struct.pack("!L", reply_sequence)), pack_opaque(cleartext) + pack_opaque(context.getMIC(cleartext))))
    arguments = bytearray(b"arguments")
    prepared = rpc.prepare_request(100003, 4, 1, arguments, auth=auth)
    arguments[:] = b"different"

    with pytest.raises(TimeoutError):
        rpc.send_prepared(prepared)

    assert rpc.retransmit(prepared) == b"result"
    assert [struct.unpack("!L", call[44:48])[0] for call in rpc.client.sent] == [7, 8]
    assert [struct.unpack("!L", call[4:8])[0] for call in rpc.client.sent] == [0x12345678, 0x12345678]
    assert all(b"arguments" in call and b"different" not in call for call in rpc.client.sent)
    assert prepared.body == b"arguments"
    assert auth.pending_sequence is None


def test_body_sequence_must_match_credential():
    context = FakeContext()
    auth = RPCSECGSSAuth(context, b"handle", "krb5i", sequence=2)
    auth.marshal_call(struct.pack("!6L", 1, 0, 2, 100003, 4, 1), b"")
    cleartext = struct.pack("!L", 3) + b"result"

    with pytest.raises(RPCSECGSSError, match="sequence"):
        auth.process_reply(RPCSEC_GSS, context.getMIC(struct.pack("!L", 2)), pack_opaque(cleartext) + pack_opaque(context.getMIC(cleartext)))


def test_rpc_opaque_auth_limit_does_not_apply_to_context_token():
    assert len(pack_opaque(b"x" * 900)) == 904
    with pytest.raises(RPCSECGSSError, match="truncated"):
        unpack_opaque(struct.pack("!L", 4) + b"x")
    with pytest.raises(Exception, match="400"):
        RPC.pack_opaque_auth(RPCSEC_GSS, b"x" * 401)
