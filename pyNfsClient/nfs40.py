import os
import secrets
import socket
from dataclasses import dataclass, field

from . import nfs4_const as const
from . import nfs4_types as types
from .nfs4_base import NFS4Error, NFS4UncertainError, NFSv4Protocol
from .nfs4_pack import NFS4Packer, NFS4Unpacker
from .rpc import RPC, RPCAuthenticationError
from .rpc_const import RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM


NO_SEQID_ADVANCE = frozenset(
    {
        const.NFS4ERR_STALE_CLIENTID,
        const.NFS4ERR_STALE_STATEID,
        const.NFS4ERR_BAD_STATEID,
        const.NFS4ERR_BAD_SEQID,
        const.NFS4ERR_BADXDR,
        const.NFS4ERR_RESOURCE,
        const.NFS4ERR_NOFILEHANDLE,
        const.NFS4ERR_MOVED,
    }
)


@dataclass(slots=True)
class OpenState40:
    filehandle: bytes
    stateid: types.Stateid4
    share_access: int
    share_deny: int
    principal: object
    opens: list["OpenReference40"] = field(default_factory=list)


@dataclass(slots=True)
class OpenReference40:
    state: OpenState40
    access: int
    deny: int
    closed: bool = False

    @property
    def filehandle(self):
        return self.state.filehandle

    @property
    def stateid(self):
        return self.state.stateid

    @property
    def share_access(self):
        return self.state.share_access

    @property
    def share_deny(self):
        return self.state.share_deny

    @property
    def principal(self):
        return self.state.principal

    @property
    def opens(self):
        return self.state.opens


@dataclass(slots=True)
class OpenOwner40:
    auth: object
    owner: bytes
    seqid: int = 0
    inflight: bool = False
    pending: object = None
    opened: list[OpenState40] = field(default_factory=list)


@dataclass(slots=True)
class PreparedOpen40:
    operation: types.ArgOp4
    owner: OpenOwner40
    share_access: int
    share_deny: int
    principal: object
    state: OpenReference40 | None = None


@dataclass(slots=True)
class PreparedClose40:
    operation: types.ArgOp4
    owner: OpenOwner40
    state: OpenReference40 | None
    principal: object
    remaining_opens: tuple[OpenReference40, ...] | None = None


@dataclass(slots=True)
class PreparedConfirm40:
    operation: types.ArgOp4
    owner: OpenOwner40
    prepared_open: PreparedOpen40
    filehandle: bytes
    open_result: types.Open4Res
    principal: object


@dataclass(slots=True)
class PendingCompound40:
    operations: tuple
    wire_operations: tuple
    tag: bytes
    auth: object
    payload: bytes
    request: object = None


class NFSv40(NFSv4Protocol):
    def __init__(self, host, port=2049, timeout=5, auth=None, *, client_identity=None):
        super().__init__(host, port, timeout, auth, client_identity)
        self.clientid = None
        self.client_name = None if client_identity is None else client_identity.owner_id
        self.client_verifier = None if client_identity is None else client_identity.verifier
        self.client_nonce = secrets.token_hex(8)
        self.establishment_auth = None
        self.open_owner_name = None
        self.open_owner_index = 0
        self.open_owners = {}

    def next_open_owner(self):
        owner = self.open_owner_name
        if self.open_owner_index:
            owner += b":" + str(self.open_owner_index).encode()
        self.open_owner_index += 1
        return owner

    def open_owner(self, auth=None, create=True):
        auth = self.effective_auth(auth)
        principal = self.auth_identity(auth)
        if principal not in self.open_owners and create:
            if self.open_owner_name is None:
                raise RuntimeError("SETCLIENTID must be confirmed before using NFSv4 state")
            self.open_owners[principal] = OpenOwner40(self.auth_snapshot(auth), self.next_open_owner())
        return self.open_owners.get(principal)

    def establish_client(self, client_name=None, verifier=None, open_owner=None, auth=None):
        if client_name is None:
            client_name = self.client_name or f"{socket.gethostname()}:{os.getpid()}:{self.client_nonce}".encode()
        elif isinstance(client_name, str):
            client_name = client_name.encode()
        if verifier is None:
            verifier = self.client_verifier or secrets.token_bytes(const.NFS4_VERIFIER_SIZE)
        response = self.compound(
            (self.setclientid_op(types.NfsClientId4(verifier, client_name), types.CallbackClient4(0, types.ClientAddr4(b"tcp", b"0.0.0.0.0.0"))),),
            tag=b"setclientid",
            auth=auth,
        )
        result = self.operation_result(response, const.OP_SETCLIENTID)
        self.compound((self.setclientid_confirm_op(result.clientid, result.setclientid_confirm),), tag=b"setclientid-confirm", auth=auth)
        self.clientid = result.clientid
        self.client_name = client_name
        self.client_verifier = verifier
        self.establishment_auth = self.auth_snapshot(self.effective_auth(auth))
        self.open_owner_name = (open_owner.encode() if isinstance(open_owner, str) else open_owner) or client_name
        self.open_owner_index = 0
        self.open_owners.clear()
        self.open_owner(auth)
        return self.clientid

    def require_client(self, auth=None):
        if self.clientid is None:
            self.establish_client(auth=auth)
        return self.open_owner(auth)

    def prepare_open(self, name, share_access=const.OPEN4_SHARE_ACCESS_READ, share_deny=const.OPEN4_SHARE_DENY_NONE, openhow=types.OpenFlag4(), claim=None, auth=None):
        owner = self.require_client(auth)
        if owner.inflight:
            raise RuntimeError("an NFSv4.0 open-owner request is already in flight")
        if claim is None:
            claim = types.OpenClaim4(const.CLAIM_NULL, file=name)
        owner.inflight = True
        return PreparedOpen40(self.open_op(owner.seqid, share_access, share_deny, types.OpenOwner4(self.clientid, owner.owner), openhow, claim), owner, share_access, share_deny, self.auth_identity(self.effective_auth(auth)))

    def prepare_close(self, state, auth=None):
        owner = self.open_owner(auth, create=False)
        if not isinstance(state, OpenReference40) or state.closed:
            raise ValueError("open reference is already closed or invalid")
        aggregate = state.state
        if owner is None or not any(item is aggregate for item in owner.opened) or not any(item is state for item in aggregate.opens) or state.principal != self.auth_identity(self.effective_auth(auth)):
            raise ValueError("open state does not belong to the effective authentication principal")
        if owner.inflight:
            raise RuntimeError("an NFSv4.0 open-owner request is already in flight")
        owner.inflight = True
        remaining_opens = tuple(item for item in aggregate.opens if item is not state)
        if remaining_opens:
            share_access, share_deny = self.aggregate_shares(remaining_opens)
            operation = self.open_downgrade_op(aggregate.stateid, owner.seqid, share_access, share_deny)
        else:
            operation = self.close_op(owner.seqid, aggregate.stateid)
        return PreparedClose40(operation, owner, state, state.principal, remaining_opens)

    def compound(self, operations, tag=b"", auth=None, check=True):
        operations = tuple(operations)
        wire_operations = ()
        payload = b""
        saved_auth = self.saved_auth(self.auth_snapshot(self.effective_auth(auth)))
        try:
            principal = self.auth_identity(self.effective_auth(auth))
            for index, operation in enumerate(operations):
                if isinstance(operation, (PreparedOpen40, PreparedClose40, PreparedConfirm40)) and operation.principal != principal:
                    raise ValueError("prepared NFSv4.0 state must use the authentication principal that created it")
                if isinstance(operation, PreparedOpen40) and (index + 1 >= len(operations) or self.operation_value(operations[index + 1]).op != const.OP_GETFH):
                    raise ValueError("an OPEN transaction requires GETFH as its next operation")
            wire_operations = tuple(self.operation_value(operation) for operation in operations)
            self.validate_operations(wire_operations)
            packer = NFS4Packer()
            packer.pack_compound_args(types.Compound4Args(tag, self.minor_version, wire_operations))
            payload = packer.get_buffer()
            response_data = self.send_compound_payload(payload, auth)
            try:
                unpacker = NFS4Unpacker(response_data)
                response = unpacker.unpack_compound_res()
                unpacker.done()
            except Exception:
                self.retain_pending(operations, wire_operations, tag, saved_auth, payload)
                raise
            if response.tag != tag:
                self.retain_pending(operations, wire_operations, tag, saved_auth, payload)
                raise NFS4Error(const.NFS4ERR_BADXDR, response=response)
            self.retain_unresolved_opens(operations, wire_operations, response, tag, saved_auth, payload)
            try:
                self.check_response(wire_operations, response, False)
            except NFS4Error as e:
                if e.status == const.NFS4ERR_BADXDR:
                    self.retain_pending(operations, wire_operations, tag, saved_auth, payload)
                raise
        except NFS4UncertainError as e:
            self.retain_pending(operations, wire_operations, tag, saved_auth, payload, e.request)
            raise
        except Exception:
            for operation in operations:
                if isinstance(operation, (PreparedOpen40, PreparedClose40, PreparedConfirm40)) and operation.owner.pending is None:
                    operation.owner.inflight = False
            raise
        for index, operation in enumerate(operations):
            if isinstance(operation, PreparedOpen40) and operation.owner.pending is None:
                self.complete_open(operation, response, index, auth)
            elif isinstance(operation, PreparedClose40) and operation.owner.pending is None:
                self.complete_close(operation, response, index)
            elif isinstance(operation, PreparedConfirm40) and operation.owner.pending is None:
                self.complete_confirm(operation, response, index, auth)
        if response.status in {const.NFS4ERR_STALE_CLIENTID, const.NFS4ERR_STALE_STATEID, const.NFS4ERR_EXPIRED}:
            self.invalidate_client()
        self.check_response(wire_operations, response, check)
        return response

    @staticmethod
    def retain_pending(operations, wire_operations, tag, auth, payload, request=None):
        pending = PendingCompound40(operations, wire_operations, tag, auth, payload, request)
        retained = False
        for operation in operations:
            if isinstance(operation, (PreparedOpen40, PreparedClose40, PreparedConfirm40)):
                operation.owner.pending = pending
                retained = True
        return pending if retained else None

    @classmethod
    def retain_unresolved_opens(cls, operations, wire_operations, response, tag, auth, payload):
        for index, operation in enumerate(operations):
            if not isinstance(operation, PreparedOpen40) or index >= len(response.resarray):
                continue
            result = response.resarray[index]
            if result.op != const.OP_OPEN or result.status != const.NFS4_OK:
                continue
            if index + 1 >= len(response.resarray) or response.resarray[index + 1].op != const.OP_GETFH or response.resarray[index + 1].status != const.NFS4_OK:
                cls.retain_pending(operations, wire_operations, tag, auth, payload)
                return True
        return False

    def send_compound_payload(self, payload, auth):
        auth = self.effective_auth(auth)
        retry_context = True
        while True:
            prepared = self.prepare_request(const.NFS_PROGRAM, const.NFS_V4, const.NFS4_PROCEDURE_COMPOUND, payload, auth=auth)
            try:
                try:
                    return self.send_prepared(prepared)
                except Exception:
                    if prepared.finished:
                        raise
                    RPC.disconnect(self)
                    RPC.connect(self)
                    prepared.reset_attempt()
                    return self.retransmit(prepared)
            except RPCAuthenticationError as e:
                self.abort_prepared(prepared)
                if retry_context and e.status in (RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM) and auth is not None and hasattr(auth, "refresh"):
                    retry_context = False
                    auth.refresh(self, const.NFS_PROGRAM, const.NFS_V4)
                    continue
                raise
            except Exception as e:
                if prepared.finished:
                    self.abort_prepared(prepared)
                    raise
                raise NFS4UncertainError(prepared) from e

    def retry_pending(self, auth=None, check=True):
        owner = self.open_owner(auth, create=False)
        if owner is None or owner.pending is None:
            raise RuntimeError("the effective principal has no unresolved NFSv4.0 state request")
        pending = owner.pending
        if self.auth_identity(self.effective_auth(pending.auth)) != self.auth_identity(self.effective_auth(auth)):
            raise ValueError("the unresolved request belongs to another authentication principal")
        try:
            if pending.request is None:
                RPC.disconnect(self)
                RPC.connect(self)
                response_data = self.send_compound_payload(pending.payload, pending.auth)
            else:
                RPC.disconnect(self)
                RPC.connect(self)
                pending.request.reset_attempt()
                response_data = self.retransmit(pending.request)
        except NFS4UncertainError as e:
            pending.request = e.request
            raise
        except Exception as e:
            if pending.request is not None and pending.request.finished:
                self.abort_prepared(pending.request)
                pending.request = None
                raise
            if pending.request is not None:
                raise NFS4UncertainError(pending.request) from e
            raise
        pending.request = None
        try:
            unpacker = NFS4Unpacker(response_data)
            response = unpacker.unpack_compound_res()
            unpacker.done()
        except Exception:
            raise
        if response.tag != pending.tag:
            raise NFS4Error(const.NFS4ERR_BADXDR, response=response)
        unresolved = self.retain_unresolved_opens(pending.operations, pending.wire_operations, response, pending.tag, pending.auth, pending.payload)
        self.check_response(pending.wire_operations, response, False)
        if unresolved:
            self.check_response(pending.wire_operations, response, check)
            return response
        for operation in pending.operations:
            if isinstance(operation, (PreparedOpen40, PreparedClose40, PreparedConfirm40)) and operation.owner.pending is pending:
                operation.owner.pending = None
        for index, operation in enumerate(pending.operations):
            if isinstance(operation, PreparedOpen40):
                self.complete_open(operation, response, index, pending.auth)
            elif isinstance(operation, PreparedClose40):
                self.complete_close(operation, response, index)
            elif isinstance(operation, PreparedConfirm40):
                self.complete_confirm(operation, response, index, pending.auth)
        if response.status in {const.NFS4ERR_STALE_CLIENTID, const.NFS4ERR_STALE_STATEID, const.NFS4ERR_EXPIRED}:
            self.invalidate_client()
        self.check_response(pending.wire_operations, response, check)
        return response

    @staticmethod
    def operation_value(operation):
        return operation.operation if isinstance(operation, (PreparedOpen40, PreparedClose40, PreparedConfirm40)) else operation

    @staticmethod
    def consume_seqid(owner, response, index):
        if index < len(response.resarray) and response.resarray[index].status not in NO_SEQID_ADVANCE:
            owner.seqid = 1 if owner.seqid == 0xFFFFFFFF else owner.seqid + 1
        owner.inflight = False

    def complete_open(self, prepared, response, index, auth):
        self.consume_seqid(prepared.owner, response, index)
        if index >= len(response.resarray) or response.resarray[index].status != const.NFS4_OK:
            return
        filehandle = response.resarray[index + 1].result
        open_result = response.resarray[index].result
        if open_result.rflags & const.OPEN4_RESULT_CONFIRM:
            confirm = self.prepare_confirm(prepared, filehandle, open_result)
            self.compound((self.putfh_op(filehandle), confirm), tag=b"open-confirm", auth=auth)
            return
        self.finalize_open(prepared, filehandle, open_result.stateid, open_result, auth)

    def finalize_open(self, prepared, filehandle, stateid, open_result, auth):
        aggregate = next((state for state in prepared.owner.opened if state.filehandle == filehandle), None)
        if aggregate is None:
            aggregate = OpenState40(filehandle, stateid, 0, 0, prepared.principal)
            prepared.owner.opened.append(aggregate)
        else:
            aggregate.stateid = stateid
        prepared.state = OpenReference40(aggregate, prepared.share_access, prepared.share_deny)
        aggregate.opens.append(prepared.state)
        aggregate.share_access, aggregate.share_deny = self.aggregate_shares(aggregate.opens)
        if open_result.delegation.delegation_type != const.OPEN_DELEGATE_NONE:
            self.compound((self.putfh_op(filehandle), self.delegreturn_op(self.delegation_stateid(open_result.delegation))), tag=b"delegreturn", auth=auth)

    def prepare_confirm(self, prepared_open, filehandle, open_result):
        if prepared_open.owner.inflight:
            raise RuntimeError("an NFSv4.0 open-owner request is already in flight")
        prepared_open.owner.inflight = True
        operation = self.open_confirm_op(open_result.stateid, prepared_open.owner.seqid)
        return PreparedConfirm40(operation, prepared_open.owner, prepared_open, filehandle, open_result, prepared_open.principal)

    def complete_confirm(self, prepared, response, index, auth):
        self.consume_seqid(prepared.owner, response, index)
        if index >= len(response.resarray) or response.resarray[index].status != const.NFS4_OK:
            return
        self.finalize_open(prepared.prepared_open, prepared.filehandle, response.resarray[index].result, prepared.open_result, auth)

    def complete_close(self, prepared, response, index):
        self.consume_seqid(prepared.owner, response, index)
        if prepared.state is None or index >= len(response.resarray) or response.resarray[index].status != const.NFS4_OK:
            return
        aggregate = prepared.state.state
        if prepared.remaining_opens:
            aggregate.stateid = response.resarray[index].result
            aggregate.opens[:] = prepared.remaining_opens
            aggregate.share_access, aggregate.share_deny = self.aggregate_shares(aggregate.opens)
        else:
            aggregate.opens.clear()
            aggregate.share_access = 0
            aggregate.share_deny = 0
            prepared.owner.opened[:] = [state for state in prepared.owner.opened if state is not aggregate]
        prepared.state.closed = True

    @staticmethod
    def aggregate_shares(opens):
        share_access = 0
        share_deny = 0
        for opened in opens:
            share_access |= opened.access
            share_deny |= opened.deny
        return share_access, share_deny

    def invalidate_client(self):
        self.clientid = None
        self.establishment_auth = None
        self.open_owner_name = None
        self.open_owner_index = 0
        self.open_owners.clear()

    @staticmethod
    def delegation_stateid(delegation):
        if delegation.delegation_type == const.OPEN_DELEGATE_READ:
            return delegation.read.stateid
        if delegation.delegation_type == const.OPEN_DELEGATE_WRITE:
            return delegation.write.stateid
        raise ValueError("OPEN result does not contain a delegation")

    def renew(self):
        if self.clientid is not None:
            self.compound((self.renew_op(self.clientid),), tag=b"renew", auth=self.saved_auth(self.establishment_auth))

    def disconnect(self):
        if self.client is not None:
            for owner in tuple(self.open_owners.values()):
                auth = self.saved_auth(owner.auth)
                if owner.pending is not None:
                    try:
                        self.retry_pending(auth, check=False)
                    except Exception:
                        continue
                for state in tuple(owner.opened):
                    while state.opens:
                        try:
                            request = self.prepare_close(state.opens[0], auth)
                            self.compound((self.putfh_op(state.filehandle), request), tag=b"close", auth=auth)
                        except Exception:
                            if owner.pending is None:
                                owner.inflight = False
                            break
        self.open_owners.clear()
        super().disconnect()


__all__ = ("NFSv40", "NFS4Error", "OpenState40", "OpenReference40", "PreparedOpen40", "PreparedClose40")
