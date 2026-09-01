from . import nfs4_types as types40
from . import nfs41_const as const
from . import nfs41_types as types
from . import nfs42_const as const42
from .nfs4_pack import NFS4CodecError, NFS4Packer, NFS4Unpacker, require


class NFS41Packer(NFS4Packer):
    minor_versions = frozenset({const.NFS4_MINOR_VERSION})
    argument_operations = const.NFS4_OPERATIONS
    result_operations = const.NFS4_RESULT_OPERATIONS
    statuses = frozenset(const.NFSSTAT4)

    def pack_create_how(self, value):
        value = require(value, types40.CreateHow4, "create how")
        if value.mode != const.EXCLUSIVE4_1:
            return super().pack_create_how(value)
        self.pack_enum4(value.mode, {const.EXCLUSIVE4_1}, "createmode4")
        value = require(getattr(value, "createboth", None), types.CreatVerfAttr4, "exclusive create verifier and attributes")
        self.pack_fixed(value.verifier, const.NFS4_VERIFIER_SIZE, "create verifier")
        self.pack_fattr(value.attrs)

    def pack_open_claim(self, value):
        value = require(value, types40.OpenClaim4, "open claim")
        if value.claim not in {const.CLAIM_FH, const.CLAIM_DELEG_CUR_FH, const.CLAIM_DELEG_PREV_FH}:
            return super().pack_open_claim(value)
        self.pack_enum4(value.claim, {const.CLAIM_FH, const.CLAIM_DELEG_CUR_FH, const.CLAIM_DELEG_PREV_FH}, "open_claim_type4")
        if value.claim == const.CLAIM_DELEG_CUR_FH:
            self.pack_stateid(require(getattr(value, "delegate_stateid", None), types.Stateid4, "delegation claim state ID"))

    def pack_none_delegation(self, value):
        value = require(value, types.OpenNoneDelegation4, "extended no-delegation result")
        self.pack_enum4(value.why, const.WHY_NO_DELEGATION4, "why_no_delegation4")
        if value.why == const.WND4_CONTENTION:
            self.pack_bool4(require(value.server_will_push_deleg, bool, "server push-delegation indication"))
        elif value.why == const.WND4_RESOURCE:
            self.pack_bool4(require(value.server_will_signal_avail, bool, "server delegation-availability indication"))

    def pack_delegation(self, value):
        value = require(value, types40.OpenDelegation4, "delegation")
        if value.delegation_type != const.OPEN_DELEGATE_NONE_EXT:
            return super().pack_delegation(value)
        self.pack_delegation_type(value.delegation_type)
        self.pack_none_delegation(require(getattr(value, "none_ext", None), types.OpenNoneDelegation4, "extended no-delegation result"))

    def pack_delegation_type(self, value):
        self.pack_enum4(value, {const.OPEN_DELEGATE_NONE, const.OPEN_DELEGATE_READ, const.OPEN_DELEGATE_WRITE, const.OPEN_DELEGATE_NONE_EXT}, "open_delegation_type4")

    def pack_optional(self, values, pack_item, label):
        if len(values) > 1:
            raise NFS4CodecError(f"{label} has more than one element")
        self.pack_array(values, pack_item)

    def pack_sessionid(self, value):
        self.pack_fixed(value, const.NFS4_SESSIONID_SIZE, "session ID")

    def pack_client_owner(self, value):
        self.pack_fixed(require(value, types.ClientOwner4, "client owner").verifier, const.NFS4_VERIFIER_SIZE, "client owner verifier")
        self.pack_opaque_limit(value.ownerid, const.NFS4_OPAQUE_LIMIT, "client owner ID")

    def pack_server_owner(self, value):
        self.pack_uint64(require(value, types.ServerOwner4, "server owner").minor_id)
        self.pack_opaque_limit(value.major_id, const.NFS4_OPAQUE_LIMIT, "server owner ID")

    def pack_impl_id(self, value):
        self.pack_utf8(require(value, types.NfsImplId4, "implementation ID").domain)
        self.pack_utf8(value.name)
        self.pack_time(value.date)

    def pack_state_protect_a(self, value):
        self.pack_enum4(require(value, types.StateProtect4A, "state protection").how, const.STATE_PROTECT_HOW4, "state_protect_how4")
        if value.how != const.SP4_NONE:
            raise NFS4CodecError("only SP4_NONE state protection is implemented")

    def pack_state_protect_r(self, value):
        self.pack_enum4(require(value, types.StateProtect4R, "state protection").how, const.STATE_PROTECT_HOW4, "state_protect_how4")
        if value.how != const.SP4_NONE:
            raise NFS4CodecError("only SP4_NONE state protection is implemented")

    def pack_channel_attrs(self, value):
        value = require(value, types.ChannelAttrs4, "channel attributes")
        self.pack_uint32(value.headerpadsize)
        self.pack_uint32(value.maxrequestsize)
        self.pack_uint32(value.maxresponsesize)
        self.pack_uint32(value.maxresponsesize_cached)
        self.pack_uint32(value.maxoperations)
        self.pack_uint32(value.maxrequests)
        self.pack_optional(value.rdma_ird, self.pack_uint32, "RDMA IRD")

    def pack_extension_arg(self, value):
        match value.op:
            case const.OP_BIND_CONN_TO_SESSION:
                value = require(value.arg, types.BindConnToSession4Args, "BIND_CONN_TO_SESSION arguments")
                self.pack_sessionid(value.sessionid)
                self.pack_enum4(value.direction, const.CHANNEL_DIR_FROM_CLIENT4, "channel_dir_from_client4")
                self.pack_bool4(value.use_conn_in_rdma_mode)
            case const.OP_EXCHANGE_ID:
                value = require(value.arg, types.ExchangeId4Args, "EXCHANGE_ID arguments")
                self.pack_client_owner(value.client_owner)
                self.pack_uint32(value.flags)
                self.pack_state_protect_a(value.state_protect)
                self.pack_optional(value.client_impl_id, self.pack_impl_id, "client implementation ID")
            case const.OP_CREATE_SESSION:
                value = require(value.arg, types.CreateSession4Args, "CREATE_SESSION arguments")
                self.pack_uint64(value.clientid)
                self.pack_uint32(value.sequence)
                self.pack_uint32(value.flags)
                self.pack_channel_attrs(value.fore_chan_attrs)
                self.pack_channel_attrs(value.back_chan_attrs)
                self.pack_uint32(value.cb_program)
                if value.sec_parms:
                    raise NFS4CodecError("callback security parameters are not implemented")
                self.pack_uint32(0)
            case const.OP_DESTROY_SESSION:
                self.pack_sessionid(require(value.arg, types.DestroySession4Args, "DESTROY_SESSION arguments").sessionid)
            case const.OP_SEQUENCE:
                value = require(value.arg, types.Sequence4Args, "SEQUENCE arguments")
                self.pack_sessionid(value.sessionid)
                self.pack_uint32(value.sequenceid)
                self.pack_uint32(value.slotid)
                self.pack_uint32(value.highest_slotid)
                self.pack_bool4(value.cachethis)
            case const.OP_DESTROY_CLIENTID:
                self.pack_uint64(require(value.arg, types.DestroyClientId4Args, "DESTROY_CLIENTID arguments").clientid)
            case const.OP_RECLAIM_COMPLETE:
                self.pack_bool4(require(value.arg, types.ReclaimComplete4Args, "RECLAIM_COMPLETE arguments").one_fs)
            case _:
                super().pack_extension_arg(value)

    def pack_extension_result(self, value):
        if value.status != const.NFS4_OK:
            return super().pack_extension_result(value)
        match value.op:
            case const.OP_BIND_CONN_TO_SESSION:
                result = require(value.result, types.BindConnToSession4Res, "BIND_CONN_TO_SESSION result")
                self.pack_sessionid(result.sessionid)
                self.pack_enum4(result.direction, const.CHANNEL_DIR_FROM_SERVER4, "channel_dir_from_server4")
                self.pack_bool4(result.use_conn_in_rdma_mode)
            case const.OP_EXCHANGE_ID:
                result = require(value.result, types.ExchangeId4Res, "EXCHANGE_ID result")
                self.pack_uint64(result.clientid)
                self.pack_uint32(result.sequenceid)
                self.pack_uint32(result.flags)
                self.pack_state_protect_r(result.state_protect)
                self.pack_server_owner(result.server_owner)
                self.pack_opaque_limit(result.server_scope, const.NFS4_OPAQUE_LIMIT, "server scope")
                self.pack_optional(result.server_impl_id, self.pack_impl_id, "server implementation ID")
            case const.OP_CREATE_SESSION:
                result = require(value.result, types.CreateSession4Res, "CREATE_SESSION result")
                self.pack_sessionid(result.sessionid)
                self.pack_uint32(result.sequence)
                self.pack_uint32(result.flags)
                self.pack_channel_attrs(result.fore_chan_attrs)
                self.pack_channel_attrs(result.back_chan_attrs)
            case const.OP_SEQUENCE:
                result = require(value.result, types.Sequence4Res, "SEQUENCE result")
                self.pack_sessionid(result.sessionid)
                self.pack_uint32(result.sequenceid)
                self.pack_uint32(result.slotid)
                self.pack_uint32(result.highest_slotid)
                self.pack_uint32(result.target_highest_slotid)
                self.pack_uint32(result.status_flags)
            case const.OP_DESTROY_SESSION | const.OP_DESTROY_CLIENTID | const.OP_RECLAIM_COMPLETE:
                if value.result is not None:
                    raise TypeError(f"operation {value.op} takes no result data")
            case _:
                super().pack_extension_result(value)


class NFS41Unpacker(NFS4Unpacker):
    minor_versions = NFS41Packer.minor_versions
    argument_operations = NFS41Packer.argument_operations
    result_operations = NFS41Packer.result_operations
    statuses = NFS41Packer.statuses

    def unpack_create_how(self):
        mode = self.unpack_enum4({const.UNCHECKED4, const.GUARDED4, const.EXCLUSIVE4, const.EXCLUSIVE4_1}, "createmode4")
        if mode in {const.UNCHECKED4, const.GUARDED4}:
            return types.CreateHow4(mode, createattrs=self.unpack_fattr())
        if mode == const.EXCLUSIVE4:
            return types.CreateHow4(mode, createverf=self.unpack_fixed(const.NFS4_VERIFIER_SIZE))
        return types.CreateHow4(mode, createboth=types.CreatVerfAttr4(self.unpack_fixed(const.NFS4_VERIFIER_SIZE), self.unpack_fattr()))

    def unpack_open_claim(self):
        claim = self.unpack_enum4({const.CLAIM_NULL, const.CLAIM_PREVIOUS, const.CLAIM_DELEGATE_CUR, const.CLAIM_DELEGATE_PREV, const.CLAIM_FH, const.CLAIM_DELEG_CUR_FH, const.CLAIM_DELEG_PREV_FH}, "open_claim_type4")
        if claim == const.CLAIM_NULL:
            return types.OpenClaim4(claim, file=self.unpack_utf8())
        if claim == const.CLAIM_PREVIOUS:
            return types.OpenClaim4(claim, delegate_type=self.unpack_delegation_type())
        if claim == const.CLAIM_DELEGATE_CUR:
            return types.OpenClaim4(claim, delegate_cur_info=types.OpenClaimDelegateCur4(self.unpack_stateid(), self.unpack_utf8()))
        if claim == const.CLAIM_DELEGATE_PREV:
            return types.OpenClaim4(claim, file_delegate_prev=self.unpack_utf8())
        if claim == const.CLAIM_DELEG_CUR_FH:
            return types.OpenClaim4(claim, delegate_stateid=self.unpack_stateid())
        return types.OpenClaim4(claim)

    def unpack_none_delegation(self):
        why = self.unpack_enum4(const.WHY_NO_DELEGATION4, "why_no_delegation4")
        if why == const.WND4_CONTENTION:
            return types.OpenNoneDelegation4(why, server_will_push_deleg=self.unpack_bool4())
        if why == const.WND4_RESOURCE:
            return types.OpenNoneDelegation4(why, server_will_signal_avail=self.unpack_bool4())
        return types.OpenNoneDelegation4(why)

    def unpack_delegation(self):
        delegation_type = self.unpack_delegation_type()
        if delegation_type == const.OPEN_DELEGATE_READ:
            return types.OpenDelegation4(delegation_type, read=types.OpenReadDelegation4(self.unpack_stateid(), self.unpack_bool4(), self.unpack_ace()))
        if delegation_type == const.OPEN_DELEGATE_WRITE:
            return types.OpenDelegation4(delegation_type, write=types.OpenWriteDelegation4(self.unpack_stateid(), self.unpack_bool4(), self.unpack_space_limit(), self.unpack_ace()))
        if delegation_type == const.OPEN_DELEGATE_NONE_EXT:
            return types.OpenDelegation4(delegation_type, none_ext=self.unpack_none_delegation())
        return types.OpenDelegation4()

    def unpack_delegation_type(self):
        return self.unpack_enum4({const.OPEN_DELEGATE_NONE, const.OPEN_DELEGATE_READ, const.OPEN_DELEGATE_WRITE, const.OPEN_DELEGATE_NONE_EXT}, "open_delegation_type4")

    def unpack_optional(self, unpack_item, label):
        count = self.unpack_uint32()
        if count > 1:
            raise NFS4CodecError(f"{label} has more than one element")
        return tuple(unpack_item() for _ in range(count))

    def unpack_sessionid(self):
        return self.unpack_fixed(const.NFS4_SESSIONID_SIZE)

    def unpack_client_owner(self):
        return types.ClientOwner4(self.unpack_fixed(const.NFS4_VERIFIER_SIZE), self.unpack_opaque_limit(const.NFS4_OPAQUE_LIMIT, "client owner ID"))

    def unpack_server_owner(self):
        return types.ServerOwner4(self.unpack_uint64(), self.unpack_opaque_limit(const.NFS4_OPAQUE_LIMIT, "server owner ID"))

    def unpack_impl_id(self):
        return types.NfsImplId4(self.unpack_utf8(), self.unpack_utf8(), self.unpack_time())

    def unpack_state_protect_a(self):
        how = self.unpack_enum4(const.STATE_PROTECT_HOW4, "state_protect_how4")
        if how != const.SP4_NONE:
            raise NFS4CodecError("only SP4_NONE state protection is implemented")
        return types.StateProtect4A(how)

    def unpack_state_protect_r(self):
        how = self.unpack_enum4(const.STATE_PROTECT_HOW4, "state_protect_how4")
        if how != const.SP4_NONE:
            raise NFS4CodecError("only SP4_NONE state protection is implemented")
        return types.StateProtect4R(how)

    def unpack_channel_attrs(self):
        return types.ChannelAttrs4(
            self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32(),
            self.unpack_optional(self.unpack_uint32, "RDMA IRD"),
        )

    def unpack_extension_arg(self, op):
        match op:
            case const.OP_BIND_CONN_TO_SESSION:
                return types.ArgOp4(op, types.BindConnToSession4Args(self.unpack_sessionid(), self.unpack_enum4(const.CHANNEL_DIR_FROM_CLIENT4, "channel_dir_from_client4"), self.unpack_bool4()))
            case const.OP_EXCHANGE_ID:
                return types.ArgOp4(op, types.ExchangeId4Args(self.unpack_client_owner(), self.unpack_uint32(), self.unpack_state_protect_a(), self.unpack_optional(self.unpack_impl_id, "client implementation ID")))
            case const.OP_CREATE_SESSION:
                clientid = self.unpack_uint64()
                sequence = self.unpack_uint32()
                flags = self.unpack_uint32()
                fore_chan_attrs = self.unpack_channel_attrs()
                back_chan_attrs = self.unpack_channel_attrs()
                cb_program = self.unpack_uint32()
                sec_parms_count = self.unpack_uint32()
                if sec_parms_count:
                    raise NFS4CodecError("callback security parameters are not implemented")
                return types.ArgOp4(op, types.CreateSession4Args(clientid, sequence, flags, fore_chan_attrs, back_chan_attrs, cb_program))
            case const.OP_DESTROY_SESSION:
                return types.ArgOp4(op, types.DestroySession4Args(self.unpack_sessionid()))
            case const.OP_SEQUENCE:
                return types.ArgOp4(op, types.Sequence4Args(self.unpack_sessionid(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_bool4()))
            case const.OP_DESTROY_CLIENTID:
                return types.ArgOp4(op, types.DestroyClientId4Args(self.unpack_uint64()))
            case const.OP_RECLAIM_COMPLETE:
                return types.ArgOp4(op, types.ReclaimComplete4Args(self.unpack_bool4()))
            case _:
                return super().unpack_extension_arg(op)

    def unpack_extension_result(self, op, status):
        if status != const.NFS4_OK:
            return super().unpack_extension_result(op, status)
        match op:
            case const.OP_BIND_CONN_TO_SESSION:
                return types.BindConnToSession4Res(self.unpack_sessionid(), self.unpack_enum4(const.CHANNEL_DIR_FROM_SERVER4, "channel_dir_from_server4"), self.unpack_bool4())
            case const.OP_EXCHANGE_ID:
                return types.ExchangeId4Res(
                    self.unpack_uint64(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_state_protect_r(), self.unpack_server_owner(),
                    self.unpack_opaque_limit(const.NFS4_OPAQUE_LIMIT, "server scope"), self.unpack_optional(self.unpack_impl_id, "server implementation ID"),
                )
            case const.OP_CREATE_SESSION:
                return types.CreateSession4Res(self.unpack_sessionid(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_channel_attrs(), self.unpack_channel_attrs())
            case const.OP_SEQUENCE:
                return types.Sequence4Res(self.unpack_sessionid(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32())
            case _:
                return super().unpack_extension_result(op, status)


class NFS42Packer(NFS41Packer):
    minor_versions = frozenset({const42.NFS4_MINOR_VERSION})
    statuses = frozenset(const42.NFSSTAT4)


class NFS42Unpacker(NFS41Unpacker):
    minor_versions = NFS42Packer.minor_versions
    statuses = NFS42Packer.statuses
