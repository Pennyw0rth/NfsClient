import errno
import logging
import secrets
import socket
import struct
import time

from .rpc_const import (
    ACCEPT_STATUS, AUTH_ERROR, AUTH_NONE, AUTH_REASON, AUTH_SYS,
    CALL, MSG_ACCEPTED, MSG_DENIED, PROG_MISMATCH, REJECT_STATUS, REPLY,
    RPC_MISMATCH, RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM, SUCCESS,
)


logger = logging.getLogger(__package__)


class RPCProtocolError(Exception):
    pass


class RPCAuthenticationError(RPCProtocolError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"RPC_AUTH_ERROR: {AUTH_REASON.get(status, status)}")


class RPCAcceptError(RPCProtocolError):
    def __init__(self, status, low=None, high=None):
        self.status = status
        self.low = low
        self.high = high
        if status == PROG_MISMATCH:
            super().__init__(f"RPC program version mismatch; server supports {low} through {high}")
        else:
            super().__init__(ACCEPT_STATUS.get(status, f"unknown RPC acceptance status {status}"))


class RPCPreparedRequest:
    def __init__(self, xid, call_header, body, auth, call):
        self.xid = xid
        self.call_header = call_header
        self.body = body
        self.auth = auth
        self.call = call
        self.reply_size = None
        self.sent = False
        self.finished = False

    def retry(self):
        if self.auth is not None and hasattr(self.auth, "marshal_retry"):
            self.call = self.auth.marshal_retry(self.call_header, self.body)

    def reset_attempt(self):
        if self.finished:
            raise RPCProtocolError("RPC prepared request is already finished")
        if self.auth is not None and hasattr(self.auth, "abort_request"):
            self.auth.abort_request()

    def abort(self):
        if not self.finished and self.auth is not None and hasattr(self.auth, "abort_request"):
            self.auth.abort_request()
        self.finished = True


class RPC(object):
    """Synchronous ONC RPC client with AUTH_NONE, AUTH_SYS, and auth hooks.

    ONC RPC uses XDR, so integers are unsigned 32-bit values in network byte
    order and variable-length fields are padded to four-byte boundaries. TCP
    record markers sit outside the XDR CALL and REPLY structures. See RFC 5531
    Sections 8.2, 9, and 11 and RFC 4506 Section 3.

    ``auth=None`` produces an empty AUTH_NONE credential. A dictionary produces
    an AUTH_SYS credential, which asserts UNIX identity values but does not prove
    them cryptographically. Stateful mechanisms such as RPCSEC_GSS provide an
    object with ``marshal_call`` and ``process_reply`` methods because their MIC
    must cover exact serialized RPC fields and their replies must be verified.
    See RFC 2203 Section 5 and RFC 7530 Section 3.
    """

    connections = []

    def __init__(self, host, port, timeout, max_response_size=64 * 1024 * 1024):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.client = None
        self.client_port = None

    def request(self, program, program_version, procedure, data=None, message_type=CALL, version=2, auth=None):
        """Encode one RFC 5531 Section 9 CALL and return its validated REPLY."""
        retry_context = True
        while True:
            try:
                return self.send_prepared(self.prepare_request(program, program_version, procedure, data, message_type, version, auth))
            except RPCAuthenticationError as e:
                # Release the RFC 2203 sequence state before refreshing or failing.
                if auth is not None and hasattr(auth, "abort_request"):
                    auth.abort_request()
                if (
                    retry_context
                    and e.status in (RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM)
                    and auth is not None
                    and hasattr(auth, "refresh")
                ):
                    # RFC 2203 Section 5.3.3.3 requires context refresh and retry for these two statuses.
                    retry_context = False
                    auth.refresh(self, program, program_version)
                    continue
                raise
            except Exception as e:
                if auth is not None and hasattr(auth, "abort_request"):
                    auth.abort_request()
                raise

    def prepare_request(self, program, program_version, procedure, data=None, message_type=CALL, version=2, auth=None):
        """Serialize one call so its XID and arguments survive a retransmission."""
        if self.client is None:
            raise RPCProtocolError("RPC client is not connected")
        xid = secrets.randbits(32)
        # RFC 5531 Section 9: xid, CALL, RPC version, program, program version, procedure.
        call_header = struct.pack("!6L", xid, message_type, version, program, program_version, procedure)
        body = b"" if data is None else bytes(data)
        if auth is not None and hasattr(auth, "marshal_call"):
            # RFC 2203 Section 5.3.1 signs the fixed header through the credential.
            call = auth.marshal_call(call_header, body)
        else:
            # RFC 5531 Section 9 places credential, verifier, and arguments after the fixed CALL fields.
            call = call_header + self.pack_credential(auth) + self.pack_opaque_auth(AUTH_NONE, b"") + body
        return RPCPreparedRequest(xid, call_header, body, auth, call)

    def send_prepared(self, prepared):
        """Send the first attempt of a prepared call and receive its reply."""
        if prepared.finished:
            raise RPCProtocolError("RPC prepared request is already finished")
        if prepared.sent:
            raise RPCProtocolError("RPC prepared request was already sent; use retransmit")
        prepared.sent = True
        return self.execute_prepared(prepared)

    def retransmit(self, prepared):
        """Retry the same XID and arguments with authentication-appropriate bytes."""
        if prepared.finished:
            raise RPCProtocolError("RPC prepared request is already finished")
        if not prepared.sent:
            raise RPCProtocolError("RPC prepared request has not been sent")
        prepared.retry()
        return self.execute_prepared(prepared)

    def execute_prepared(self, prepared):
        self.send_record(prepared.call)
        reply = self.recv_record()
        prepared.reply_size = len(reply)
        if len(reply) < 12:
            raise RPCProtocolError("RPC reply is shorter than its fixed header")

        # RFC 5531 Section 9 starts every REPLY with xid, REPLY, and the reply-union discriminator.
        reply_xid, reply_type, reply_state = struct.unpack("!3L", reply[:12])
        if reply_xid != prepared.xid:
            raise RPCProtocolError(f"RPC reply XID {reply_xid:#x} does not match call XID {prepared.xid:#x}")
        if reply_type != REPLY:
            raise RPCProtocolError(f"expected RPC REPLY, received message type {reply_type}")
        if reply_state == MSG_DENIED:
            prepared.abort()
            self.raise_denied_reply(reply[12:])
        if reply_state != MSG_ACCEPTED:
            raise RPCProtocolError(f"unknown RPC reply state {reply_state}")

        # RFC 5531 Section 9 puts the verifier before accept_status; MSG_ACCEPTED does not imply SUCCESS.
        # RFC 2203 Section 5.3.3.2 authenticates the matching GSS request sequence with that verifier.
        verifier_flavor, verifier, offset = self.unpack_opaque_auth(reply, 12)
        if len(reply) < offset + 4:
            raise RPCProtocolError("RPC accepted reply has no acceptance status")
        accept_status = struct.unpack("!L", reply[offset:offset + 4])[0]
        if accept_status != SUCCESS:
            # RFC 2203 Section 5.3.3.2 still defines the verifier when accept_status is not SUCCESS.
            if prepared.auth is not None and hasattr(prepared.auth, "process_error_reply"):
                prepared.auth.process_error_reply(verifier_flavor, verifier)
            prepared.finished = True
            self.raise_accept_error(accept_status, reply[offset + 4:])

        if prepared.auth is not None and hasattr(prepared.auth, "process_reply"):
            # RFC 2203 Sections 5.3.2 and 5.3.3.2 define MIC verification and result unwrapping.
            result = prepared.auth.process_reply(verifier_flavor, verifier, reply[offset + 4:])
            prepared.finished = True
            return result
        prepared.finished = True
        logger.debug("RPC call succeeded")
        return reply[offset + 4:]

    @staticmethod
    def abort_prepared(prepared):
        prepared.abort()

    def connect(self):
        # RFC 7530 Section 3.1 requires NFSv4 TCP support; force stream lookup to avoid OS-dependent ordering.
        address_family, socket_type, protocol, canonical_name, socket_address = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)[0]
        self.client = socket.socket(address_family, socket_type)
        self.client.settimeout(self.timeout)
        # NFS servers may enforce the traditional reserved-port check. This
        # client deliberately has no unprivileged-source-port fallback.
        self.bind_privileged_port()
        self.client.connect(socket_address)
        self.connections.append(self)

    def bind_privileged_port(self):
        """Bind one available reserved source port before connecting.

        Address collisions are retried. Missing permission is terminal because
        silently continuing from an ephemeral port would violate this contract.
        """
        for attempt in range(120_000):
            try:
                # Cycle deterministically through reserved ports 1 through 1023.
                self.client_port = (attempt % 1023) + 1
                self.client.bind(("", self.client_port))
                logger.debug(f"RPC client bound to port {self.client_port}")
                return
            except PermissionError as e:
                if e.errno != errno.EACCES:
                    raise
                logger.error("Permission denied! Could not bind to low port, NFS functionality unavailable!")
                raise RPCProtocolError("RPC client requires permission to bind a privileged source port") from e
            except OSError as e:
                logger.warning(f"Socket port binding with {self.client_port} failed in loop {attempt}, try again.")
        logger.error("Could not bind client port. No ports left on the client.")
        raise RPCProtocolError("RPC client could not bind a privileged source port after 120000 attempts")

    def disconnect(self):
        if self.client is None:
            return
        self.client.close()
        self.client = None
        if self in self.connections:
            self.connections.remove(self)
        logger.debug(f"RPC connection closed; source port was {self.client_port}")

    @classmethod
    def disconnect_all(cls):
        for connection in cls.connections[:]:
            connection.disconnect()

    def send_record(self, payload):
        """Send one RPC message using RFC 5531 Section 11 record marking."""
        if len(payload) > 0x7fffffff:
            raise RPCProtocolError("RPC record is too large")
        # RFC 5531 Section 11: bit 31 marks the last fragment; the low 31 bits hold its length.
        self.client.sendall(struct.pack("!L", 0x80000000 | len(payload)) + payload)

    def recv_record(self):
        """Reassemble an RFC 5531 Section 11 RPC record from TCP fragments."""
        record = bytearray()
        while True:
            fragment_header = struct.unpack("!L", self.recv_exact(4))[0]
            # Mask away the final-fragment bit to recover the byte count.
            fragment_size = fragment_header & 0x7fffffff
            # Apply the limit to the complete reassembled record, not each part.
            if len(record) + fragment_size > self.max_response_size:
                raise RPCProtocolError(f"RPC reply exceeds the configured {self.max_response_size}-byte limit")
            record.extend(self.recv_exact(fragment_size))
            if fragment_header & 0x80000000:
                return bytes(record)

    def recv(self):
        """Receive one RFC 5531 Section 11 fragment for legacy callers."""
        fragment_header = self.recv_exact(4)
        return fragment_header + self.recv_exact(struct.unpack("!L", fragment_header)[0] & 0x7fffffff)

    def recv_exact(self, size):
        """Read exactly ``size`` bytes despite normal short TCP reads."""
        data = bytearray()
        while len(data) < size:
            chunk = self.client.recv(size - len(data))
            if not chunk:
                # An empty TCP read is EOF; it is not a zero-length fragment.
                raise RPCProtocolError(f"RPC connection closed with {size - len(data)} bytes left to receive")
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def pack_opaque_auth(flavor, body):
        """Encode ``opaque_auth`` as flavor, length, body, and XDR padding.

        RFC 5531 Section 8.2 limits the body to 400 bytes. Its length excludes
        padding; RFC 4506 Section 3 pads the encoded field to a four-byte boundary.
        A MIC over the serialized credential includes that padding.
        """
        if len(body) > 400:
            raise RPCProtocolError("RPC opaque authentication body exceeds 400 bytes")
        # ``-length % 4`` yields 0..3 zero bytes without a special case.
        return struct.pack("!2L", flavor, len(body)) + body + b"\x00" * (-len(body) % 4)

    @classmethod
    def pack_credential(cls, auth):
        """Encode an AUTH_NONE or AUTH_SYS credential as ``opaque_auth``.

        RFC 5531 Section 10.1 defines AUTH_NONE and Appendix A defines AUTH_SYS.
        AUTH_SYS dictionaries contain ``flavor``, ``machine_name``, ``uid``,
        ``gid``, and an ``aux_gid`` sequence. These values are claims supplied to
        the server; AUTH_SYS does not cryptographically verify the local account.
        """
        if auth is None:
            return cls.pack_opaque_auth(AUTH_NONE, b"")
        if not isinstance(auth, dict) or auth.get("flavor") != AUTH_SYS:
            raise RPCProtocolError("unknown RPC authentication method")

        machine_name = auth["machine_name"].encode() if isinstance(auth["machine_name"], str) else auth["machine_name"]
        auxiliary_groups = auth.get("aux_gid", [])
        if len(machine_name) > 255:
            raise RPCProtocolError("AUTH_SYS machine name exceeds 255 bytes")
        if len(auxiliary_groups) > 16:
            raise RPCProtocolError("AUTH_SYS credential exceeds 16 auxiliary groups")
        # RFC 5531 Appendix A: stamp | machine name | uid | primary gid | auxiliary gids; the verifier is AUTH_NONE.
        credential = struct.pack("!2L", int(time.time()) & 0xffffffff, len(machine_name))
        credential += machine_name + b"\x00" * (-len(machine_name) % 4)
        credential += struct.pack("!3L", auth["uid"], auth["gid"], len(auxiliary_groups))
        credential += b"".join(struct.pack("!L", group) for group in auxiliary_groups)
        return cls.pack_opaque_auth(AUTH_SYS, credential)

    @staticmethod
    def unpack_opaque_auth(message, offset):
        """Decode RFC 5531 Section 8.2 ``opaque_auth`` with RFC 4506 padding."""
        if len(message) < offset + 8:
            raise RPCProtocolError("truncated RPC opaque authentication header")
        flavor, length = struct.unpack("!2L", message[offset:offset + 8])
        offset += 8
        # Round the declared length up to its XDR-aligned wire size. The caller
        # must continue after the padding, not immediately after the body.
        padded_length = (length + 3) & ~3
        if length > 400 or len(message) < offset + padded_length:
            raise RPCProtocolError("invalid RPC opaque authentication body")
        return flavor, message[offset:offset + length], offset + padded_length

    @staticmethod
    def raise_denied_reply(reply):
        """Decode the MSG_DENIED union arm and raise its protocol error.

        The union is defined by RFC 5531 Section 9.
        Denial happens before program dispatch and has no accepted-reply
        verifier. RPC_MISMATCH concerns RPC version 2 itself; AUTH_ERROR concerns
        the supplied credential or verifier.
        """
        if len(reply) < 4:
            raise RPCProtocolError("truncated denied RPC reply")
        reject_status = struct.unpack("!L", reply[:4])[0]
        if reject_status == RPC_MISMATCH:
            if len(reply) < 12:
                raise RPCProtocolError("truncated RPC version mismatch reply")
            low, high = struct.unpack("!2L", reply[4:12])
            raise RPCProtocolError(f"RPC version mismatch; server supports {low} through {high}")
        if reject_status == AUTH_ERROR:
            if len(reply) < 8:
                raise RPCProtocolError("truncated RPC authentication error reply")
            auth_status = struct.unpack("!L", reply[4:8])[0]
            raise RPCAuthenticationError(auth_status)
        raise RPCProtocolError(f"RPC call denied: {REJECT_STATUS.get(reject_status, reject_status)}")

    @staticmethod
    def raise_accept_error(accept_status, body):
        """Decode a non-success acceptance status after RPC dispatch.

        The union is defined by RFC 5531 Section 9.
        PROG_MISMATCH means RPC version 2 worked but the requested program version
        did not, so its union arm carries the server's supported version range.
        """
        if accept_status == PROG_MISMATCH:
            if len(body) < 8:
                raise RPCProtocolError("truncated RPC program version mismatch reply")
            low, high = struct.unpack("!2L", body[:8])
            raise RPCAcceptError(accept_status, low, high)
        raise RPCAcceptError(accept_status)
