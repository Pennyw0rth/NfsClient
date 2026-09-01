import os
import secrets
import socket
import threading

from . import nfs41_const as const
from . import nfs41_types as types
from .nfs4_base import NFS4Error, NFSv4Protocol
from .nfs41_pack import NFS41Packer, NFS41Unpacker
from .rpc import RPC, RPCAuthenticationError
from .rpc_const import RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM


FORE_CHANNEL = types.ChannelAttrs4(0, 4 * 1024 * 1024, 4 * 1024 * 1024, 1024 * 1024, 64, 1)
BACK_CHANNEL = types.ChannelAttrs4(0, 1024 * 1024, 1024 * 1024, 1024 * 1024, 8, 1)
UNSEQUENCED_OPERATIONS = frozenset({const.OP_BIND_CONN_TO_SESSION, const.OP_EXCHANGE_ID, const.OP_CREATE_SESSION, const.OP_DESTROY_SESSION, const.OP_SEQUENCE, const.OP_DESTROY_CLIENTID})
RAW_OPERATIONS = frozenset({const.OP_BIND_CONN_TO_SESSION, const.OP_EXCHANGE_ID, const.OP_CREATE_SESSION, const.OP_DESTROY_SESSION, const.OP_DESTROY_CLIENTID})
CACHED_OPERATIONS = frozenset({
    const.OP_CLOSE,
    const.OP_COMMIT,
    const.OP_CREATE,
    const.OP_DELEGPURGE,
    const.OP_DELEGRETURN,
    const.OP_LINK,
    const.OP_LOCK,
    const.OP_LOCKU,
    const.OP_OPEN,
    const.OP_OPENATTR,
    const.OP_OPEN_DOWNGRADE,
    const.OP_REMOVE,
    const.OP_RENAME,
    const.OP_SETATTR,
    const.OP_WRITE,
    const.OP_RECLAIM_COMPLETE,
})


class NFSv41(NFSv4Protocol):
    minor_version = const.NFS4_MINOR_VERSION
    legal_operations = const.NFS4_OPERATIONS
    packer_class = NFS41Packer
    unpacker_class = NFS41Unpacker

    def __init__(self, host, port=2049, timeout=5, auth=None, *, client_identity=None):
        super().__init__(host, port, timeout, auth, client_identity)
        self.clientid = None
        self.client_name = None if client_identity is None else client_identity.owner_id
        self.client_verifier = None if client_identity is None else client_identity.verifier
        self.client_nonce = secrets.token_hex(8)
        self.establishment_auth = None
        self.sessionid = None
        self.session_auth = None
        self.fore_chan_attrs = None
        self.back_chan_attrs = None
        self.slot_sequenceid = 1
        self.session_status_flags = 0
        self.session_broken = False
        self.session_lock = threading.RLock()

    @staticmethod
    def bind_conn_to_session_op(sessionid, direction=const.CDFC4_FORE, use_conn_in_rdma_mode=False):
        return types.ArgOp4(const.OP_BIND_CONN_TO_SESSION, types.BindConnToSession4Args(sessionid, direction, use_conn_in_rdma_mode))

    @staticmethod
    def exchange_id_op(client_owner, flags=const.EXCHGID4_FLAG_USE_NON_PNFS, state_protect=types.StateProtect4A(), client_impl_id=()):
        return types.ArgOp4(const.OP_EXCHANGE_ID, types.ExchangeId4Args(client_owner, flags, state_protect, tuple(client_impl_id)))

    @staticmethod
    def create_session_op(clientid, sequence, fore_chan_attrs=FORE_CHANNEL, back_chan_attrs=BACK_CHANNEL, flags=0, cb_program=0, sec_parms=()):
        return types.ArgOp4(const.OP_CREATE_SESSION, types.CreateSession4Args(clientid, sequence, flags, fore_chan_attrs, back_chan_attrs, cb_program, tuple(sec_parms)))

    @staticmethod
    def destroy_session_op(sessionid):
        return types.ArgOp4(const.OP_DESTROY_SESSION, types.DestroySession4Args(sessionid))

    @staticmethod
    def sequence_op(sessionid, sequenceid, slotid=0, highest_slotid=0, cachethis=True):
        return types.ArgOp4(const.OP_SEQUENCE, types.Sequence4Args(sessionid, sequenceid, slotid, highest_slotid, cachethis))

    @staticmethod
    def destroy_clientid_op(clientid):
        return types.ArgOp4(const.OP_DESTROY_CLIENTID, types.DestroyClientId4Args(clientid))

    @staticmethod
    def reclaim_complete_op(one_fs=False):
        return types.ArgOp4(const.OP_RECLAIM_COMPLETE, types.ReclaimComplete4Args(one_fs))

    def compound_raw(self, operations, tag=b"", auth=None, check=True):
        operations = tuple(operations)
        if len(operations) != 1 or operations[0].op not in RAW_OPERATIONS:
            raise ValueError("compound_raw() accepts one session setup or teardown operation")
        self.validate_operations(operations)
        packer = self.packer_class()
        packer.pack_compound_args(types.Compound4Args(tag, self.minor_version, operations))
        if self.fore_chan_attrs is not None and len(packer.get_buffer()) > self.fore_chan_attrs.maxrequestsize:
            raise NFS4Error(const.NFS4ERR_REQ_TOO_BIG)
        response_data = self.send_compound_payload(packer.get_buffer(), auth)
        if self.fore_chan_attrs is not None and len(response_data) > self.fore_chan_attrs.maxresponsesize:
            raise NFS4Error(const.NFS4ERR_REP_TOO_BIG, response=response_data)
        unpacker = self.unpacker_class(response_data)
        response = unpacker.unpack_compound_res()
        unpacker.done()
        if response.tag != tag:
            raise NFS4Error(const.NFS4ERR_BADXDR, response=response)
        self.check_response(operations, response, check)
        return response

    def send_compound_payload(self, payload, auth, bind_session=False, cached=False):
        auth = self.effective_auth(auth)
        retry_context = True
        while True:
            prepared = self.prepare_request(const.NFS_PROGRAM, const.NFS_V4, const.NFS4_PROCEDURE_COMPOUND, payload, auth=auth)
            if self.fore_chan_attrs is not None and len(prepared.call) > self.fore_chan_attrs.maxrequestsize:
                self.abort_prepared(prepared)
                raise NFS4Error(const.NFS4ERR_REQ_TOO_BIG)
            try:
                try:
                    response = self.send_prepared(prepared)
                except Exception:
                    if prepared.finished:
                        raise
                    self.reconnect_transport(prepared)
                    if bind_session and self.sessionid is not None:
                        self.bind_connection(auth=auth)
                    response = self.retransmit(prepared)
                if self.fore_chan_attrs is not None and prepared.reply_size is not None and prepared.reply_size > self.fore_chan_attrs.maxresponsesize:
                    raise NFS4Error(const.NFS4ERR_REP_TOO_BIG)
                if cached and prepared.reply_size is not None and prepared.reply_size > self.fore_chan_attrs.maxresponsesize_cached:
                    raise NFS4Error(const.NFS4ERR_REP_TOO_BIG_TO_CACHE)
                return response
            except RPCAuthenticationError as e:
                self.abort_prepared(prepared)
                if retry_context and e.status in (RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM) and auth is not None and hasattr(auth, "refresh"):
                    retry_context = False
                    auth.refresh(self, const.NFS_PROGRAM, const.NFS_V4)
                    continue
                raise
            except Exception:
                self.abort_prepared(prepared)
                raise

    def reconnect_transport(self, prepared):
        RPC.disconnect(self)
        prepared.reset_attempt()
        RPC.connect(self)

    def request_auth(self, auth):
        return self.saved_auth(self.auth_snapshot(self.effective_auth(auth)))

    def cache_response(self, operations):
        return any(operation.op in CACHED_OPERATIONS for operation in operations)

    def check_sequence(self, request, response):
        if not response.resarray or response.resarray[0].op != const.OP_SEQUENCE:
            self.session_broken = True
            raise NFS4Error(const.NFS4ERR_BADXDR, const.OP_SEQUENCE, 0, response)
        result = response.resarray[0]
        if result.status != const.NFS4_OK:
            self.session_broken = True
            return
        if not isinstance(result.result, types.Sequence4Res) or result.result.sessionid != request.arg.sessionid or result.result.sequenceid != request.arg.sequenceid or result.result.slotid != 0 or result.result.highest_slotid >= self.fore_chan_attrs.maxrequests or result.result.target_highest_slotid >= self.fore_chan_attrs.maxrequests:
            self.session_broken = True
            raise NFS4Error(const.NFS4ERR_BADXDR, const.OP_SEQUENCE, 0, response)
        self.slot_sequenceid = (self.slot_sequenceid + 1) & 0xFFFFFFFF
        self.session_status_flags = result.result.status_flags

    def compound(self, operations, tag=b"", auth=None, check=True):
        operations = tuple(operations)
        if any(operation.op in UNSEQUENCED_OPERATIONS for operation in operations):
            raise ValueError("session setup and teardown operations require compound_raw()")
        with self.session_lock:
            request_auth = self.request_auth(auth)
            self.ensure_session(request_auth)
            if self.session_broken:
                raise RuntimeError("the NFSv4 session can no longer issue requests")
            sequence = self.sequence_op(self.sessionid, self.slot_sequenceid, cachethis=self.cache_response(operations))
            wire_operations = (sequence, *operations)
            self.validate_operations(wire_operations)
            if len(wire_operations) > self.fore_chan_attrs.maxoperations:
                raise NFS4Error(const.NFS4ERR_TOO_MANY_OPS)
            packer = self.packer_class()
            packer.pack_compound_args(types.Compound4Args(tag, self.minor_version, wire_operations))
            if len(packer.get_buffer()) > self.fore_chan_attrs.maxrequestsize:
                raise NFS4Error(const.NFS4ERR_REQ_TOO_BIG)
            try:
                response_data = self.send_compound_payload(packer.get_buffer(), request_auth, bind_session=True, cached=sequence.arg.cachethis)
                if len(response_data) > self.fore_chan_attrs.maxresponsesize:
                    raise NFS4Error(const.NFS4ERR_REP_TOO_BIG, response=response_data)
                unpacker = self.unpacker_class(response_data)
                response = unpacker.unpack_compound_res()
                unpacker.done()
                if response.tag != tag:
                    raise NFS4Error(const.NFS4ERR_BADXDR, response=response)
                self.check_response(wire_operations, response, False)
                self.check_sequence(sequence, response)
            except Exception:
                self.session_broken = True
                raise
            self.check_response(wire_operations, response, check)
            return response

    def ensure_session(self, auth=None):
        if self.sessionid is None:
            self.establish_session(auth=auth)
        elif self.session_broken:
            raise RuntimeError("the NFSv4 session can no longer issue requests")
        return self.sessionid

    def establish_client(self, client_name=None, verifier=None, open_owner=None, auth=None):
        return self.establish_session(client_name, verifier, auth)

    def establish_session(self, client_name=None, verifier=None, auth=None):
        with self.session_lock:
            if self.sessionid is not None:
                if not self.session_broken:
                    return self.sessionid
                try:
                    self.destroy_session()
                except Exception:
                    self.clear_session()
            if client_name is None:
                client_name = self.client_name or f"{socket.gethostname()}:{os.getpid()}:{self.client_nonce}".encode()
            elif isinstance(client_name, str):
                client_name = client_name.encode()
            if verifier is None:
                verifier = self.client_verifier or secrets.token_bytes(const.NFS4_VERIFIER_SIZE)
            request_auth = self.request_auth(auth)
            response = self.compound_raw((self.exchange_id_op(types.ClientOwner4(verifier, client_name)),), tag=b"exchange-id", auth=request_auth)
            exchange = self.operation_result(response, const.OP_EXCHANGE_ID)
            self.clientid = exchange.clientid
            self.client_name = client_name
            self.client_verifier = verifier
            self.establishment_auth = self.auth_snapshot(self.effective_auth(request_auth))
            if exchange.state_protect.how != const.SP4_NONE or exchange.flags & const.EXCHGID4_FLAG_MASK_PNFS not in const.EXCHGID4_PNFS_ROLES:
                raise NFS4Error(const.NFS4ERR_NOTSUPP, const.OP_EXCHANGE_ID, 0, response)
            response = self.compound_raw((self.create_session_op(exchange.clientid, exchange.sequenceid),), tag=b"create-session", auth=request_auth)
            created = self.operation_result(response, const.OP_CREATE_SESSION)
            self.sessionid = created.sessionid
            self.session_auth = self.establishment_auth
            self.session_broken = True
            if created.sequence != exchange.sequenceid or not self.channel_accepted(FORE_CHANNEL, created.fore_chan_attrs, minimum_operations=2) or not self.channel_accepted(BACK_CHANNEL, created.back_chan_attrs, backchannel=True) or created.flags & (const.CREATE_SESSION4_FLAG_CONN_BACK_CHAN | const.CREATE_SESSION4_FLAG_CONN_RDMA):
                raise NFS4Error(const.NFS4ERR_BADXDR, const.OP_CREATE_SESSION, 0, response)
            self.fore_chan_attrs = created.fore_chan_attrs
            self.back_chan_attrs = created.back_chan_attrs
            self.slot_sequenceid = 1
            self.session_status_flags = 0
            self.session_broken = False
            response = self.compound((self.reclaim_complete_op(),), tag=b"reclaim-complete", auth=request_auth, check=False)
            if response.status not in {const.NFS4_OK, const.NFS4ERR_COMPLETE_ALREADY}:
                self.session_broken = True
                raise NFS4Error(response.status, const.OP_RECLAIM_COMPLETE, len(response.resarray) - 1, response)
            return self.sessionid

    @staticmethod
    def channel_accepted(offered, accepted, minimum_operations=0, backchannel=False):
        fields = ("headerpadsize", "maxrequestsize", "maxresponsesize", "maxresponsesize_cached")
        return accepted.maxrequestsize > 0 and accepted.maxresponsesize > 0 and accepted.maxoperations >= minimum_operations and accepted.maxrequests >= 1 and (not backchannel or (accepted.maxoperations == offered.maxoperations and accepted.maxrequests == offered.maxrequests)) and len(accepted.rdma_ird) <= len(offered.rdma_ird) and all(getattr(accepted, field) <= getattr(offered, field) for field in fields)

    def bind_connection(self, direction=const.CDFC4_FORE, use_conn_in_rdma_mode=False, auth=None):
        if direction != const.CDFC4_FORE or use_conn_in_rdma_mode:
            raise ValueError("only a non-RDMA forechannel connection is supported")
        with self.session_lock:
            self.ensure_session(auth)
            request_auth = self.request_auth(self.saved_auth(self.session_auth) if auth is None else auth)
            response = self.compound_raw((self.bind_conn_to_session_op(self.sessionid, direction, use_conn_in_rdma_mode),), tag=b"bind-connection", auth=request_auth)
            result = self.operation_result(response, const.OP_BIND_CONN_TO_SESSION)
            if result.sessionid != self.sessionid or result.direction != const.CDFS4_FORE or result.use_conn_in_rdma_mode:
                raise NFS4Error(const.NFS4ERR_BADXDR, const.OP_BIND_CONN_TO_SESSION, 0, response)
            return response

    def reclaim_complete(self, one_fs=False, auth=None):
        return self.compound((self.reclaim_complete_op(one_fs),), tag=b"reclaim-complete", auth=auth)

    def renew(self, auth=None):
        return self.compound((), tag=b"renew", auth=auth)

    def clear_session(self):
        self.sessionid = None
        self.session_auth = None
        self.fore_chan_attrs = None
        self.back_chan_attrs = None
        self.slot_sequenceid = 1
        self.session_status_flags = 0
        self.session_broken = False

    def destroy_session(self, auth=None):
        if self.sessionid is None:
            return False
        with self.session_lock:
            sessionid = self.sessionid
            request_auth = self.request_auth(self.saved_auth(self.session_auth) if auth is None else auth)
            self.compound_raw((self.destroy_session_op(sessionid),), tag=b"destroy-session", auth=request_auth)
            self.clear_session()
            return True

    def destroy_client(self, auth=None):
        if self.clientid is None:
            return False
        with self.session_lock:
            clientid = self.clientid
            request_auth = self.request_auth(self.saved_auth(self.establishment_auth) if auth is None else auth)
            self.compound_raw((self.destroy_clientid_op(clientid),), tag=b"destroy-clientid", auth=request_auth)
            self.clientid = None
            self.client_name = None if self.client_identity is None else self.client_identity.owner_id
            self.client_verifier = None if self.client_identity is None else self.client_identity.verifier
            self.establishment_auth = None
            return True

    def disconnect(self):
        if self.client is not None:
            try:
                self.destroy_session()
            except Exception:
                pass
            try:
                self.destroy_client()
            except Exception:
                pass
        self.clear_session()
        self.clientid = None
        self.establishment_auth = None
        super().disconnect()


__all__ = ("NFSv41",)
