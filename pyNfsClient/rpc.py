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


class RPC(object):
    """Synchronous ONC RPC client with AUTH_NONE, AUTH_SYS, and auth hooks.

    ONC RPC uses XDR, so integers are unsigned 32-bit values in network byte
    order and variable-length fields are padded to four-byte boundaries. TCP
    record markers sit outside the XDR CALL and REPLY structures.

    ``auth=None`` produces an empty AUTH_NONE credential. A dictionary produces
    an AUTH_SYS credential, which asserts UNIX identity values but does not prove
    them cryptographically. Stateful mechanisms such as RPCSEC_GSS provide an
    object with ``marshal_call`` and ``process_reply`` methods because their MIC
    must cover exact serialized RPC fields and their replies must be verified.
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
        """Encode one CALL, send it, validate its REPLY, and return result bytes."""
        if self.client is None:
            raise RPCProtocolError("RPC client is not connected")

        retry_context = True
        while True:
            try:
                xid = secrets.randbits(32)
                # Fixed CALL header, in wire order:
                # xid, CALL, RPC version, program, program version, procedure.
                call_header = struct.pack("!6L", xid, message_type, version, program, program_version, procedure)
                body = b"" if data is None else data
                if auth is not None and hasattr(auth, "marshal_call"):
                    # RPCSEC_GSS builds the credential and verifier together: its
                    # verifier is a MIC over the fixed header plus the credential.
                    call = auth.marshal_call(call_header, body)
                else:
                    # A normal CALL continues with credential, verifier, and the
                    # already-XDR-encoded procedure arguments.
                    call = call_header + self.pack_credential(auth) + self.pack_opaque_auth(AUTH_NONE, b"") + body

                self.send_record(call)
                reply = self.recv_record()
                if len(reply) < 12:
                    raise RPCProtocolError("RPC reply is shorter than its fixed header")

                # Every REPLY begins with xid, REPLY, and a reply discriminator.
                # The discriminator selects the accepted or denied union arm.
                reply_xid, reply_type, reply_state = struct.unpack("!3L", reply[:12])
                if reply_xid != xid:
                    raise RPCProtocolError(f"RPC reply XID {reply_xid:#x} does not match call XID {xid:#x}")
                if reply_type != REPLY:
                    raise RPCProtocolError(f"expected RPC REPLY, received message type {reply_type}")
                if reply_state == MSG_DENIED:
                    self.raise_denied_reply(reply[12:])
                if reply_state != MSG_ACCEPTED:
                    raise RPCProtocolError(f"unknown RPC reply state {reply_state}")

                # MSG_ACCEPTED means that the server understood the RPC envelope;
                # accept_status still determines whether program dispatch worked.
                # An accepted reply contains an opaque verifier before its
                # acceptance status. AUTH_NONE uses an empty verifier, while a
                # GSS verifier authenticates the matching request sequence.
                verifier_flavor, verifier, offset = self.unpack_opaque_auth(reply, 12)
                if len(reply) < offset + 4:
                    raise RPCProtocolError("RPC accepted reply has no acceptance status")
                accept_status = struct.unpack("!L", reply[offset:offset + 4])[0]
                if accept_status != SUCCESS:
                    # A GSS reply verifier remains meaningful when RPC dispatch
                    # reports a program/procedure error, so verify it first.
                    if auth is not None and hasattr(auth, "process_error_reply"):
                        auth.process_error_reply(verifier_flavor, verifier)
                    self.raise_accept_error(accept_status, reply[offset + 4:])

                if auth is not None and hasattr(auth, "process_reply"):
                    # RPCSEC_GSS verifies the server MIC here, then verifies or
                    # unwraps the procedure result according to krb5/krb5i/krb5p.
                    return auth.process_reply(verifier_flavor, verifier, reply[offset + 4:])
                logger.debug("RPC call succeeded")
                return reply[offset + 4:]
            except RPCAuthenticationError as e:
                # The auth object may have reserved sequence state for this call.
                # Release it before either refreshing the context or failing.
                if auth is not None and hasattr(auth, "abort_request"):
                    auth.abort_request()
                if (
                    retry_context
                    and e.status in (RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM)
                    and auth is not None
                    and hasattr(auth, "refresh")
                ):
                    # RFC 2203 permits an expired/broken RPCSEC_GSS context to be
                    # recreated. Retry once so a persistent failure is surfaced.
                    retry_context = False
                    auth.refresh(self, program, program_version)
                    continue
                raise
            except Exception as e:
                if auth is not None and hasattr(auth, "abort_request"):
                    auth.abort_request()
                raise

    def connect(self):
        # Force TCP to avoid OS-dependent getaddrinfo ordering differences.
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
                # Cycle deterministically through reserved ports 1 through 1022.
                self.client_port = (attempt % 1022) + 1
                self.client.bind(("", self.client_port))
                logger.debug("RPC client bound to port %d", self.client_port)
                return
            except PermissionError as e:
                if e.errno != errno.EACCES:
                    raise
                logger.error("Permission denied! Could not bind to low port, NFS functionality unavailable!")
                raise RPCProtocolError("RPC client requires permission to bind a privileged source port") from e
            except OSError as e:
                logger.warning("Socket port binding with %s failed in loop %d, try again.", self.client_port, attempt)
        logger.error("Could not bind client port. No ports left on the client.")
        raise RPCProtocolError("RPC client could not bind a privileged source port after 120000 attempts")

    def disconnect(self):
        if self.client is None:
            return
        self.client.close()
        self.client = None
        if self in self.connections:
            self.connections.remove(self)
        logger.debug("RPC connection closed; source port was %s", self.client_port)

    @classmethod
    def disconnect_all(cls):
        for connection in cls.connections[:]:
            connection.disconnect()

    def send_record(self, payload):
        """Send one complete RPC message as a single TCP record fragment."""
        if len(payload) > 0x7fffffff:
            raise RPCProtocolError("RPC record is too large")
        # RFC record marking: bit 31 means "last fragment" and the lower
        # 31 bits carry the fragment length. This implementation emits one.
        self.client.sendall(struct.pack("!L", 0x80000000 | len(payload)) + payload)

    def recv_record(self):
        """Reassemble all TCP fragments belonging to one RPC reply record."""
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
        """Receive one fragment including its record marker for legacy callers."""
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

        The length describes only ``body``. Padding is present on the wire but is
        not returned as part of a decoded body. A MIC over the complete serialized
        credential still includes those padding bytes.
        """
        if len(body) > 400:
            raise RPCProtocolError("RPC opaque authentication body exceeds 400 bytes")
        # ``-length % 4`` yields 0..3 zero bytes without a special case.
        return struct.pack("!2L", flavor, len(body)) + body + b"\x00" * (-len(body) % 4)

    @classmethod
    def pack_credential(cls, auth):
        """Encode an AUTH_NONE or AUTH_SYS credential as ``opaque_auth``.

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
        # AUTH_SYS body, before the outer opaque_auth wrapper:
        # stamp | machine-name length | machine name + padding |
        # uid | primary gid | auxiliary-gid count | auxiliary gids.
        # The CALL verifier remains AUTH_NONE; AUTH_SYS itself is not a MIC.
        credential = struct.pack("!2L", int(time.time()) & 0xffffffff, len(machine_name))
        credential += machine_name + b"\x00" * (-len(machine_name) % 4)
        credential += struct.pack("!3L", auth["uid"], auth["gid"], len(auxiliary_groups))
        credential += b"".join(struct.pack("!L", group) for group in auxiliary_groups)
        return cls.pack_opaque_auth(AUTH_SYS, credential)

    @staticmethod
    def unpack_opaque_auth(message, offset):
        """Decode ``opaque_auth`` and return flavor, unpadded body, next offset."""
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

        PROG_MISMATCH means RPC version 2 worked but the requested program version
        did not, so its union arm carries the server's supported version range.
        """
        if accept_status == PROG_MISMATCH:
            if len(body) < 8:
                raise RPCProtocolError("truncated RPC program version mismatch reply")
            low, high = struct.unpack("!2L", body[:8])
            raise RPCProtocolError(f"RPC program version mismatch; server supports {low} through {high}")
        raise RPCProtocolError(ACCEPT_STATUS.get(accept_status, f"unknown RPC acceptance status {accept_status}"))
