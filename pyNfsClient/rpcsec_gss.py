import secrets
import struct

from .rpc import RPC, RPCProtocolError
from .rpc_const import AUTH_NONE, RPCSEC_GSS


RPCSEC_GSS_VERSION = 1
RPCSEC_GSS_DATA = 0
RPCSEC_GSS_INIT = 1
RPCSEC_GSS_CONTINUE_INIT = 2
RPCSEC_GSS_DESTROY = 3

RPC_GSS_SVC_NONE = 1
RPC_GSS_SVC_INTEGRITY = 2
RPC_GSS_SVC_PRIVACY = 3

GSS_S_COMPLETE = 0
GSS_S_CONTINUE_NEEDED = 1
MAXSEQ = 0x80000000

GSS_SERVICES = {
    "krb5": RPC_GSS_SVC_NONE,
    "krb5i": RPC_GSS_SVC_INTEGRITY,
    "krb5p": RPC_GSS_SVC_PRIVACY,
}


class RPCSECGSSError(RPCProtocolError):
    pass


def pack_opaque(data):
    return struct.pack("!L", len(data)) + data + b"\x00" * (-len(data) % 4)


def unpack_opaque(data, offset=0):
    if len(data) < offset + 4:
        raise RPCSECGSSError("truncated XDR opaque length")
    length = struct.unpack("!L", data[offset : offset + 4])[0]
    offset += 4
    padded_length = (length + 3) & ~3
    if len(data) < offset + padded_length:
        raise RPCSECGSSError("truncated XDR opaque value")
    return data[offset : offset + length], offset + padded_length


def pack_gss_credential(procedure, sequence, service, handle):
    return struct.pack("!4L", RPCSEC_GSS_VERSION, procedure, sequence, service) + pack_opaque(handle)


class RPCSECGSSControl:
    def __init__(self, procedure, handle):
        self.procedure = procedure
        self.handle = handle

    def marshal_call(self, call_header, body):
        return (
            call_header
            + RPC.pack_opaque_auth(RPCSEC_GSS, pack_gss_credential(self.procedure, 0, RPC_GSS_SVC_NONE, self.handle))
            + RPC.pack_opaque_auth(AUTH_NONE, b"")
            + body
        )

    @staticmethod
    def process_reply(verifier_flavor, verifier, body):
        return verifier_flavor, verifier, body


class RPCSECGSSAuth:
    def __init__(self, context, handle, service, sequence=None, window=0, initiator_factory=None):
        if service not in GSS_SERVICES:
            raise ValueError(f"RPCSEC_GSS service must be one of {', '.join(GSS_SERVICES)}")
        self.context = context
        self.handle = handle
        self.service_name = service
        self.service = GSS_SERVICES[service]
        self.sequence = secrets.randbelow(MAXSEQ - 1) + 1 if sequence is None else sequence
        self.pending_sequence = None
        self.window = window
        self.procedure = RPCSEC_GSS_DATA
        self.initiator_factory = initiator_factory

    @classmethod
    def establish(cls, rpc, program, program_version, initiator, service="krb5i", initiator_factory=None):
        if initiator_factory is None:
            if hasattr(initiator, "host") and hasattr(initiator, "credentials"):
                initiator_factory = lambda: type(initiator)(initiator.host, initiator.credentials)
            else:
                initiator_factory = type(initiator)
        handle = b""
        token = initiator.start()
        procedure = RPCSEC_GSS_INIT
        while True:
            verifier_flavor, verifier, response = rpc.request(program, program_version, 0, data=pack_opaque(token), auth=RPCSECGSSControl(procedure, handle))
            handle, major, minor, window, server_token = cls.unpack_init_response(response)
            if major not in (GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED):
                raise RPCSECGSSError(f"GSS context creation failed with status {major:#x}/{minor:#x}")
            token = initiator.step(server_token)
            if major == GSS_S_COMPLETE:
                if token is not None:
                    raise RPCSECGSSError("GSS initiator did not complete when the server completed")
                if verifier_flavor != RPCSEC_GSS:
                    raise RPCSECGSSError("completed RPCSEC_GSS context has no GSS reply verifier")
                initiator.context.verifyMIC(struct.pack("!L", window), verifier)
                return cls(initiator.context, handle, service, window=window, initiator_factory=initiator_factory)
            if token is None:
                raise RPCSECGSSError("GSS server requested continuation without a client token")
            procedure = RPCSEC_GSS_CONTINUE_INIT

    @staticmethod
    def unpack_init_response(data):
        handle, offset = unpack_opaque(data)
        if len(data) < offset + 12:
            raise RPCSECGSSError("truncated RPCSEC_GSS context response")
        major, minor, window = struct.unpack("!3L", data[offset : offset + 12])
        token, offset = unpack_opaque(data, offset + 12)
        if offset != len(data):
            raise RPCSECGSSError("trailing bytes in RPCSEC_GSS context response")
        if not handle and major in (GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED):
            raise RPCSECGSSError("RPCSEC_GSS server returned an empty context handle")
        return handle, major, minor, window, token

    def marshal_call(self, call_header, body):
        if self.pending_sequence is not None:
            raise RPCSECGSSError("RPCSEC_GSS authentication object already has an outstanding request")
        if self.sequence >= MAXSEQ:
            raise RPCSECGSSError("RPCSEC_GSS sequence space is exhausted; establish a new context")

        self.pending_sequence = self.sequence
        self.sequence += 1
        credential = RPC.pack_opaque_auth(
            RPCSEC_GSS,
            pack_gss_credential(self.procedure, self.pending_sequence, RPC_GSS_SVC_NONE if self.procedure == RPCSEC_GSS_DESTROY else self.service, self.handle),
        )
        signed_header = call_header + credential
        return signed_header + RPC.pack_opaque_auth(RPCSEC_GSS, self.context.getMIC(signed_header)) + self.protect_body(body)

    def protect_body(self, body):
        if self.procedure == RPCSEC_GSS_DESTROY or self.service == RPC_GSS_SVC_NONE:
            return body
        cleartext = struct.pack("!L", self.pending_sequence) + body
        if self.service == RPC_GSS_SVC_INTEGRITY:
            return pack_opaque(cleartext) + pack_opaque(self.context.getMIC(cleartext))
        return pack_opaque(self.context.wrap(cleartext))

    def process_reply(self, verifier_flavor, verifier, body):
        self.verify_reply(verifier_flavor, verifier)
        result = self.unprotect_body(body)
        self.pending_sequence = None
        return result

    def process_error_reply(self, verifier_flavor, verifier):
        self.verify_reply(verifier_flavor, verifier)
        self.pending_sequence = None

    def verify_reply(self, verifier_flavor, verifier):
        if self.pending_sequence is None:
            raise RPCSECGSSError("RPCSEC_GSS reply has no matching request")
        if verifier_flavor != RPCSEC_GSS:
            raise RPCSECGSSError("RPCSEC_GSS reply has an unexpected verifier flavor")
        self.context.verifyMIC(struct.pack("!L", self.pending_sequence), verifier)

    def abort_request(self):
        self.pending_sequence = None

    def refresh(self, rpc, program, program_version):
        if self.initiator_factory is None:
            raise RPCSECGSSError("RPCSEC_GSS context cannot be refreshed without an initiator factory")
        self.abort_request()
        self.__dict__.update(type(self).establish(rpc, program, program_version, self.initiator_factory(), self.service_name, self.initiator_factory).__dict__)

    def unprotect_body(self, body):
        if self.procedure == RPCSEC_GSS_DESTROY or self.service == RPC_GSS_SVC_NONE:
            return body
        if self.service == RPC_GSS_SVC_INTEGRITY:
            cleartext, offset = unpack_opaque(body)
            checksum, offset = unpack_opaque(body, offset)
            if offset != len(body):
                raise RPCSECGSSError("trailing bytes in an integrity-protected RPCSEC_GSS reply")
            self.context.verifyMIC(cleartext, checksum)
        else:
            token, offset = unpack_opaque(body)
            if offset != len(body):
                raise RPCSECGSSError("trailing bytes in a privacy-protected RPCSEC_GSS reply")
            cleartext = self.context.unwrap(token)
        if len(cleartext) < 4 or struct.unpack("!L", cleartext[:4])[0] != self.pending_sequence:
            raise RPCSECGSSError("RPCSEC_GSS body sequence does not match its credential")
        return cleartext[4:]

    def destroy(self, rpc, program, program_version):
        self.procedure = RPCSEC_GSS_DESTROY
        try:
            rpc.request(program, program_version, 0, auth=self)
        finally:
            self.procedure = RPCSEC_GSS_DATA
