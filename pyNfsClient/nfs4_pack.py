"""XDR encoder and decoder for the NFSv4.0 forechannel."""

from typing import Any

from . import nfs4_const as const
from . import nfs4_types as types
from .xdrlib import Error as XDRError
from .xdrlib import Packer, Unpacker


class NFS4CodecError(XDRError):
    pass


def require(value: Any, expected: type | tuple[type, ...], label: str) -> Any:
    if not isinstance(value, expected):
        raise TypeError(f"{label} must be {' or '.join(item.__name__ for item in expected) if isinstance(expected, tuple) else expected.__name__}")
    return value


def utf8_bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if not isinstance(value, bytes):
        raise TypeError("UTF-8 strings must be bytes or str")
    value.decode("utf-8")
    return value


class NFS4Packer(Packer):
    def pack_uint32(self, value: int) -> None:
        if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
            raise NFS4CodecError(f"uint32 out of range: {value!r}")
        self.pack_uint(value)

    def pack_uint64(self, value: int) -> None:
        if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise NFS4CodecError(f"uint64 out of range: {value!r}")
        self.pack_uhyper(value)

    def pack_int64(self, value: int) -> None:
        if not isinstance(value, int) or not -(1 << 63) <= value < 1 << 63:
            raise NFS4CodecError(f"int64 out of range: {value!r}")
        self.pack_hyper(value)

    def pack_enum4(self, value: int, allowed: set[int] | frozenset[int], label: str) -> None:
        if value not in allowed:
            raise NFS4CodecError(f"invalid {label}: {value!r}")
        self.pack_int(value)

    def pack_bool4(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise NFS4CodecError(f"bool required, got {value!r}")
        self.pack_uint32(int(value))

    def pack_utf8(self, value: bytes | str) -> None:
        self.pack_opaque(utf8_bytes(value))

    def pack_opaque_limit(self, value: bytes, limit: int, label: str) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{label} must be bytes")
        if len(value) > limit:
            raise NFS4CodecError(f"{label} exceeds {limit} bytes")
        self.pack_opaque(value)

    def pack_fixed(self, value: bytes, length: int, label: str) -> None:
        if not isinstance(value, bytes) or len(value) != length:
            raise NFS4CodecError(f"{label} must be {length} bytes")
        self.pack_fopaque(length, value)

    def pack_bitmap(self, value: types.Bitmap4) -> None:
        self.pack_array(require(value, types.Bitmap4, "bitmap").words, self.pack_uint32)

    def pack_time(self, value: types.NfsTime4) -> None:
        self.pack_int64(require(value, types.NfsTime4, "time").seconds)
        if not 0 <= value.nseconds < 1_000_000_000:
            raise NFS4CodecError("nanoseconds must be below one second")
        self.pack_uint32(value.nseconds)

    def pack_settime(self, value: types.SetTime4) -> None:
        self.pack_enum4(require(value, types.SetTime4, "settime").set_it, {const.SET_TO_SERVER_TIME4, const.SET_TO_CLIENT_TIME4}, "time_how4")
        if value.set_it == const.SET_TO_CLIENT_TIME4:
            self.pack_time(require(value.time, types.NfsTime4, "settime.time"))

    def pack_fsid(self, value: types.Fsid4) -> None:
        self.pack_uint64(require(value, types.Fsid4, "fsid").major)
        self.pack_uint64(value.minor)

    def pack_pathname(self, value: tuple[bytes | str, ...]) -> None:
        self.pack_array(value, self.pack_utf8)

    def pack_fs_location(self, value: types.FsLocation4) -> None:
        self.pack_array(require(value, types.FsLocation4, "fs location").server, self.pack_utf8)
        self.pack_pathname(value.rootpath)

    def pack_fs_locations(self, value: types.FsLocations4) -> None:
        self.pack_pathname(require(value, types.FsLocations4, "fs locations").fs_root)
        self.pack_array(value.locations, self.pack_fs_location)

    def pack_ace(self, value: types.NfsAce4) -> None:
        self.pack_uint32(require(value, types.NfsAce4, "ACE").type)
        self.pack_uint32(value.flag)
        self.pack_uint32(value.access_mask)
        self.pack_utf8(value.who)

    def pack_specdata(self, value: types.SpecData4) -> None:
        self.pack_uint32(require(value, types.SpecData4, "specdata").specdata1)
        self.pack_uint32(value.specdata2)

    def pack_stateid(self, value: types.Stateid4) -> None:
        self.pack_uint32(require(value, types.Stateid4, "stateid").seqid)
        self.pack_fixed(value.other, const.NFS4_OTHER_SIZE, "stateid.other")

    def pack_change_info(self, value: types.ChangeInfo4) -> None:
        self.pack_bool4(require(value, types.ChangeInfo4, "change info").atomic)
        self.pack_uint64(value.before)
        self.pack_uint64(value.after)

    def pack_client_addr(self, value: types.ClientAddr4) -> None:
        self.pack_utf8(require(value, types.ClientAddr4, "client address").r_netid)
        self.pack_utf8(value.r_addr)

    def pack_callback_client(self, value: types.CallbackClient4) -> None:
        self.pack_uint32(require(value, types.CallbackClient4, "callback client").cb_program)
        self.pack_client_addr(value.cb_location)

    def pack_client_id(self, value: types.NfsClientId4) -> None:
        self.pack_fixed(require(value, types.NfsClientId4, "client id").verifier, const.NFS4_VERIFIER_SIZE, "verifier")
        self.pack_opaque_limit(value.id, const.NFS4_OPAQUE_LIMIT, "client id")

    def pack_open_owner(self, value: types.OpenOwner4) -> None:
        self.pack_uint64(require(value, types.OpenOwner4, "open owner").clientid)
        self.pack_opaque_limit(value.owner, const.NFS4_OPAQUE_LIMIT, "open owner")

    def pack_lock_owner(self, value: types.LockOwner4) -> None:
        self.pack_uint64(require(value, types.LockOwner4, "lock owner").clientid)
        self.pack_opaque_limit(value.owner, const.NFS4_OPAQUE_LIMIT, "lock owner")

    def pack_attribute(self, number: int, value: Any) -> None:
        if number == const.FATTR4_SUPPORTED_ATTRS:
            self.pack_bitmap(require(value, types.Bitmap4, "supported attributes"))
        elif number == const.FATTR4_TYPE:
            self.pack_enum4(value, set(const.NFS_FTYPE4), "nfs_ftype4")
        elif number in {
            const.FATTR4_FH_EXPIRE_TYPE,
            const.FATTR4_LEASE_TIME,
            const.FATTR4_ACLSUPPORT,
            const.FATTR4_MAXLINK,
            const.FATTR4_MAXNAME,
            const.FATTR4_MODE,
            const.FATTR4_NUMLINKS,
        }:
            self.pack_uint32(value)
        elif number in {
            const.FATTR4_CHANGE,
            const.FATTR4_SIZE,
            const.FATTR4_FILEID,
            const.FATTR4_FILES_AVAIL,
            const.FATTR4_FILES_FREE,
            const.FATTR4_FILES_TOTAL,
            const.FATTR4_MAXFILESIZE,
            const.FATTR4_MAXREAD,
            const.FATTR4_MAXWRITE,
            const.FATTR4_QUOTA_AVAIL_HARD,
            const.FATTR4_QUOTA_AVAIL_SOFT,
            const.FATTR4_QUOTA_USED,
            const.FATTR4_SPACE_AVAIL,
            const.FATTR4_SPACE_FREE,
            const.FATTR4_SPACE_TOTAL,
            const.FATTR4_SPACE_USED,
            const.FATTR4_MOUNTED_ON_FILEID,
        }:
            self.pack_uint64(value)
        elif number in {
            const.FATTR4_LINK_SUPPORT,
            const.FATTR4_SYMLINK_SUPPORT,
            const.FATTR4_NAMED_ATTR,
            const.FATTR4_UNIQUE_HANDLES,
            const.FATTR4_ARCHIVE,
            const.FATTR4_CANSETTIME,
            const.FATTR4_CASE_INSENSITIVE,
            const.FATTR4_CASE_PRESERVING,
            const.FATTR4_CHOWN_RESTRICTED,
            const.FATTR4_HIDDEN,
            const.FATTR4_HOMOGENEOUS,
            const.FATTR4_NO_TRUNC,
            const.FATTR4_SYSTEM,
        }:
            self.pack_bool4(value)
        elif number == const.FATTR4_FSID:
            self.pack_fsid(value)
        elif number == const.FATTR4_RDATTR_ERROR:
            self.pack_status(value)
        elif number == const.FATTR4_ACL:
            self.pack_array(value, self.pack_ace)
        elif number == const.FATTR4_FILEHANDLE:
            self.pack_opaque_limit(value, const.NFS4_FHSIZE, "filehandle")
        elif number == const.FATTR4_FS_LOCATIONS:
            self.pack_fs_locations(value)
        elif number in {const.FATTR4_MIMETYPE, const.FATTR4_OWNER, const.FATTR4_OWNER_GROUP}:
            self.pack_utf8(value)
        elif number == const.FATTR4_RAWDEV:
            self.pack_specdata(value)
        elif number in {
            const.FATTR4_TIME_ACCESS,
            const.FATTR4_TIME_BACKUP,
            const.FATTR4_TIME_CREATE,
            const.FATTR4_TIME_DELTA,
            const.FATTR4_TIME_METADATA,
            const.FATTR4_TIME_MODIFY,
        }:
            self.pack_time(value)
        elif number in {const.FATTR4_TIME_ACCESS_SET, const.FATTR4_TIME_MODIFY_SET}:
            self.pack_settime(value)
        else:
            raise NFS4CodecError(f"attribute {number} is not defined by RFC 3530")

    def pack_fattr(self, value: types.Fattr4) -> None:
        require(value, types.Fattr4, "attributes")
        self.pack_bitmap(value.attrmask)
        attr_packer = NFS4Packer()
        for number in sorted(value.attributes):
            attr_packer.pack_attribute(number, value.attributes[number])
        self.pack_opaque(attr_packer.get_buffer())

    def pack_create_type(self, value: types.CreateType4) -> None:
        self.pack_enum4(require(value, types.CreateType4, "create type").type, set(const.NFS_FTYPE4), "nfs_ftype4")
        if value.type == const.NF4LNK:
            self.pack_utf8(require(value.linkdata, (bytes, str), "link data"))
        elif value.type in {const.NF4BLK, const.NF4CHR}:
            self.pack_specdata(require(value.devdata, types.SpecData4, "device data"))

    def pack_open_to_lock_owner(self, value: types.OpenToLockOwner4) -> None:
        self.pack_uint32(require(value, types.OpenToLockOwner4, "open-to-lock owner").open_seqid)
        self.pack_stateid(value.open_stateid)
        self.pack_uint32(value.lock_seqid)
        self.pack_lock_owner(value.lock_owner)

    def pack_existing_lock_owner(self, value: types.ExistingLockOwner4) -> None:
        self.pack_stateid(require(value, types.ExistingLockOwner4, "existing lock owner").lock_stateid)
        self.pack_uint32(value.lock_seqid)

    def pack_locker(self, value: types.Locker4) -> None:
        self.pack_bool4(require(value, types.Locker4, "locker").new_lock_owner)
        if value.new_lock_owner:
            self.pack_open_to_lock_owner(require(value.open_owner, types.OpenToLockOwner4, "new lock owner"))
        else:
            self.pack_existing_lock_owner(require(value.lock_owner, types.ExistingLockOwner4, "existing lock owner"))

    def pack_lock_denied(self, value: types.LockDenied4) -> None:
        self.pack_uint64(require(value, types.LockDenied4, "denied lock").offset)
        self.pack_uint64(value.length)
        self.pack_lock_type(value.locktype)
        self.pack_lock_owner(value.owner)

    def pack_create_how(self, value: types.CreateHow4) -> None:
        self.pack_enum4(require(value, types.CreateHow4, "create how").mode, {const.UNCHECKED4, const.GUARDED4, const.EXCLUSIVE4}, "createmode4")
        if value.mode in {const.UNCHECKED4, const.GUARDED4}:
            self.pack_fattr(require(value.createattrs, types.Fattr4, "create attributes"))
        else:
            self.pack_fixed(require(value.createverf, bytes, "create verifier"), const.NFS4_VERIFIER_SIZE, "create verifier")

    def pack_open_flag(self, value: types.OpenFlag4) -> None:
        self.pack_enum4(require(value, types.OpenFlag4, "open flag").opentype, {const.OPEN4_NOCREATE, const.OPEN4_CREATE}, "opentype4")
        if value.opentype == const.OPEN4_CREATE:
            self.pack_create_how(require(value.how, types.CreateHow4, "open create how"))

    def pack_space_limit(self, value: types.NfsSpaceLimit4) -> None:
        self.pack_enum4(require(value, types.NfsSpaceLimit4, "space limit").limitby, {const.NFS_LIMIT_SIZE, const.NFS_LIMIT_BLOCKS}, "limit_by4")
        if value.limitby == const.NFS_LIMIT_SIZE:
            self.pack_uint64(require(value.filesize, int, "file size limit"))
        else:
            self.pack_uint32(require(value.mod_blocks, types.NfsModifiedLimit4, "block limit").num_blocks)
            self.pack_uint32(value.mod_blocks.bytes_per_block)

    def pack_open_claim(self, value: types.OpenClaim4) -> None:
        self.pack_enum4(
            require(value, types.OpenClaim4, "open claim").claim,
            {
                const.CLAIM_NULL,
                const.CLAIM_PREVIOUS,
                const.CLAIM_DELEGATE_CUR,
                const.CLAIM_DELEGATE_PREV,
            },
            "open_claim_type4",
        )
        if value.claim == const.CLAIM_NULL:
            self.pack_utf8(require(value.file, (bytes, str), "claim file"))
        elif value.claim == const.CLAIM_PREVIOUS:
            self.pack_delegation_type(require(value.delegate_type, int, "delegation type"))
        elif value.claim == const.CLAIM_DELEGATE_CUR:
            self.pack_stateid(require(value.delegate_cur_info, types.OpenClaimDelegateCur4, "delegation claim").delegate_stateid)
            self.pack_utf8(value.delegate_cur_info.file)
        else:
            self.pack_utf8(require(value.file_delegate_prev, (bytes, str), "previous delegation file"))

    def pack_delegation(self, value: types.OpenDelegation4) -> None:
        self.pack_delegation_type(require(value, types.OpenDelegation4, "delegation").delegation_type)
        if value.delegation_type == const.OPEN_DELEGATE_READ:
            self.pack_stateid(require(value.read, types.OpenReadDelegation4, "read delegation").stateid)
            self.pack_bool4(value.read.recall)
            self.pack_ace(value.read.permissions)
        elif value.delegation_type == const.OPEN_DELEGATE_WRITE:
            self.pack_stateid(require(value.write, types.OpenWriteDelegation4, "write delegation").stateid)
            self.pack_bool4(value.write.recall)
            self.pack_space_limit(value.write.space_limit)
            self.pack_ace(value.write.permissions)

    def pack_delegation_type(self, value: int) -> None:
        self.pack_enum4(
            value,
            {
                const.OPEN_DELEGATE_NONE,
                const.OPEN_DELEGATE_READ,
                const.OPEN_DELEGATE_WRITE,
            },
            "open_delegation_type4",
        )

    def pack_lock_type(self, value: int) -> None:
        self.pack_enum4(value, {const.READ_LT, const.WRITE_LT, const.READW_LT, const.WRITEW_LT}, "nfs_lock_type4")

    def pack_status(self, value: int) -> None:
        self.pack_enum4(value, set(const.NFSSTAT4), "nfsstat4")

    def pack_secinfo(self, value: types.SecInfo4) -> None:
        self.pack_uint32(require(value, types.SecInfo4, "security info").flavor)
        if value.flavor == const.RPCSEC_GSS:
            self.pack_opaque(require(value.flavor_info, types.RpcSecGssInfo4, "RPCSEC_GSS info").oid)
            self.pack_uint32(value.flavor_info.qop)
            self.pack_enum4(
                value.flavor_info.service,
                {
                    const.RPC_GSS_SVC_NONE,
                    const.RPC_GSS_SVC_INTEGRITY,
                    const.RPC_GSS_SVC_PRIVACY,
                },
                "rpc_gss_svc_t",
            )

    def pack_entry(self, value: types.Entry4) -> None:
        self.pack_uint64(require(value, types.Entry4, "directory entry").cookie)
        self.pack_utf8(value.name)
        self.pack_fattr(value.attrs)

    def pack_argop(self, value: types.ArgOp4) -> None:
        self.pack_enum4(require(value, types.ArgOp4, "argument operation").op, const.NFS4_OPERATIONS, "nfs_opnum4")
        match value.op:
            case const.OP_ACCESS:
                self.pack_uint32(require(value.arg, types.Access4Args, "ACCESS arguments").access)
            case const.OP_CLOSE:
                self.pack_uint32(require(value.arg, types.Close4Args, "CLOSE arguments").seqid)
                self.pack_stateid(value.arg.open_stateid)
            case const.OP_COMMIT:
                self.pack_uint64(require(value.arg, types.Commit4Args, "COMMIT arguments").offset)
                self.pack_uint32(value.arg.count)
            case const.OP_CREATE:
                self.pack_create_type(require(value.arg, types.Create4Args, "CREATE arguments").objtype)
                self.pack_utf8(value.arg.objname)
                self.pack_fattr(value.arg.createattrs)
            case const.OP_DELEGPURGE:
                self.pack_uint64(require(value.arg, types.DelegPurge4Args, "DELEGPURGE arguments").clientid)
            case const.OP_DELEGRETURN:
                self.pack_stateid(require(value.arg, types.DelegReturn4Args, "DELEGRETURN arguments").deleg_stateid)
            case const.OP_GETATTR:
                self.pack_bitmap(require(value.arg, types.GetAttr4Args, "GETATTR arguments").attr_request)
            case const.OP_LINK:
                self.pack_utf8(require(value.arg, types.Link4Args, "LINK arguments").newname)
            case const.OP_LOCK:
                self.pack_lock_type(require(value.arg, types.Lock4Args, "LOCK arguments").locktype)
                self.pack_bool4(value.arg.reclaim)
                self.pack_uint64(value.arg.offset)
                self.pack_uint64(value.arg.length)
                self.pack_locker(value.arg.locker)
            case const.OP_LOCKT:
                self.pack_lock_type(require(value.arg, types.LockT4Args, "LOCKT arguments").locktype)
                self.pack_uint64(value.arg.offset)
                self.pack_uint64(value.arg.length)
                self.pack_lock_owner(value.arg.owner)
            case const.OP_LOCKU:
                self.pack_lock_type(require(value.arg, types.LockU4Args, "LOCKU arguments").locktype)
                self.pack_uint32(value.arg.seqid)
                self.pack_stateid(value.arg.lock_stateid)
                self.pack_uint64(value.arg.offset)
                self.pack_uint64(value.arg.length)
            case const.OP_LOOKUP:
                self.pack_utf8(require(value.arg, types.Lookup4Args, "LOOKUP arguments").objname)
            case const.OP_NVERIFY:
                self.pack_fattr(require(value.arg, types.NVerify4Args, "NVERIFY arguments").obj_attributes)
            case const.OP_OPEN:
                self.pack_uint32(require(value.arg, types.Open4Args, "OPEN arguments").seqid)
                self.pack_uint32(value.arg.share_access)
                self.pack_uint32(value.arg.share_deny)
                self.pack_open_owner(value.arg.owner)
                self.pack_open_flag(value.arg.openhow)
                self.pack_open_claim(value.arg.claim)
            case const.OP_OPENATTR:
                self.pack_bool4(require(value.arg, types.OpenAttr4Args, "OPENATTR arguments").createdir)
            case const.OP_OPEN_CONFIRM:
                self.pack_stateid(require(value.arg, types.OpenConfirm4Args, "OPEN_CONFIRM arguments").open_stateid)
                self.pack_uint32(value.arg.seqid)
            case const.OP_OPEN_DOWNGRADE:
                self.pack_stateid(require(value.arg, types.OpenDowngrade4Args, "OPEN_DOWNGRADE arguments").open_stateid)
                self.pack_uint32(value.arg.seqid)
                self.pack_uint32(value.arg.share_access)
                self.pack_uint32(value.arg.share_deny)
            case const.OP_PUTFH:
                self.pack_opaque_limit(require(value.arg, types.PutFh4Args, "PUTFH arguments").object, const.NFS4_FHSIZE, "filehandle")
            case const.OP_READ:
                self.pack_stateid(require(value.arg, types.Read4Args, "READ arguments").stateid)
                self.pack_uint64(value.arg.offset)
                self.pack_uint32(value.arg.count)
            case const.OP_READDIR:
                self.pack_uint64(require(value.arg, types.ReadDir4Args, "READDIR arguments").cookie)
                self.pack_fixed(value.arg.cookieverf, const.NFS4_VERIFIER_SIZE, "cookie verifier")
                self.pack_uint32(value.arg.dircount)
                self.pack_uint32(value.arg.maxcount)
                self.pack_bitmap(value.arg.attr_request)
            case const.OP_REMOVE:
                self.pack_utf8(require(value.arg, types.Remove4Args, "REMOVE arguments").target)
            case const.OP_RENAME:
                self.pack_utf8(require(value.arg, types.Rename4Args, "RENAME arguments").oldname)
                self.pack_utf8(value.arg.newname)
            case const.OP_RENEW:
                self.pack_uint64(require(value.arg, types.Renew4Args, "RENEW arguments").clientid)
            case const.OP_SECINFO:
                self.pack_utf8(require(value.arg, types.SecInfo4Args, "SECINFO arguments").name)
            case const.OP_SETATTR:
                self.pack_stateid(require(value.arg, types.SetAttr4Args, "SETATTR arguments").stateid)
                self.pack_fattr(value.arg.obj_attributes)
            case const.OP_SETCLIENTID:
                self.pack_client_id(require(value.arg, types.SetClientId4Args, "SETCLIENTID arguments").client)
                self.pack_callback_client(value.arg.callback)
                self.pack_uint32(value.arg.callback_ident)
            case const.OP_SETCLIENTID_CONFIRM:
                self.pack_uint64(require(value.arg, types.SetClientIdConfirm4Args, "SETCLIENTID_CONFIRM arguments").clientid)
                self.pack_fixed(value.arg.setclientid_confirm, const.NFS4_VERIFIER_SIZE, "setclientid verifier")
            case const.OP_VERIFY:
                self.pack_fattr(require(value.arg, types.Verify4Args, "VERIFY arguments").obj_attributes)
            case const.OP_WRITE:
                self.pack_stateid(require(value.arg, types.Write4Args, "WRITE arguments").stateid)
                self.pack_uint64(value.arg.offset)
                self.pack_enum4(value.arg.stable, {const.UNSTABLE4, const.DATA_SYNC4, const.FILE_SYNC4}, "stable_how4")
                self.pack_opaque(value.arg.data)
            case const.OP_RELEASE_LOCKOWNER:
                self.pack_lock_owner(require(value.arg, types.ReleaseLockOwner4Args, "RELEASE_LOCKOWNER arguments").lock_owner)
            case _:
                if value.arg is not None:
                    raise TypeError(f"operation {value.op} takes no arguments")

    def pack_result_data(self, value: types.ResOp4) -> None:
        match value.op:
            case const.OP_ACCESS if value.status == const.NFS4_OK:
                self.pack_uint32(require(value.result, types.Access4Res, "ACCESS result").supported)
                self.pack_uint32(value.result.access)
            case const.OP_CLOSE if value.status == const.NFS4_OK:
                self.pack_stateid(require(value.result, types.Stateid4, "CLOSE result"))
            case const.OP_COMMIT if value.status == const.NFS4_OK:
                self.pack_fixed(require(value.result, types.Commit4Res, "COMMIT result").writeverf, const.NFS4_VERIFIER_SIZE, "write verifier")
            case const.OP_CREATE if value.status == const.NFS4_OK:
                self.pack_change_info(require(value.result, types.Create4Res, "CREATE result").cinfo)
                self.pack_bitmap(value.result.attrset)
            case const.OP_GETATTR if value.status == const.NFS4_OK:
                self.pack_fattr(require(value.result, types.Fattr4, "GETATTR result"))
            case const.OP_GETFH if value.status == const.NFS4_OK:
                self.pack_opaque_limit(require(value.result, bytes, "GETFH result"), const.NFS4_FHSIZE, "filehandle")
            case const.OP_LINK if value.status == const.NFS4_OK:
                self.pack_change_info(require(value.result, types.Link4Res, "LINK result").cinfo)
            case const.OP_LOCK if value.status == const.NFS4_OK:
                self.pack_stateid(require(value.result, types.Stateid4, "LOCK result"))
            case const.OP_LOCK | const.OP_LOCKT if value.status == const.NFS4ERR_DENIED:
                self.pack_lock_denied(require(value.result, types.LockDenied4, "denied lock"))
            case const.OP_LOCKU if value.status == const.NFS4_OK:
                self.pack_stateid(require(value.result, types.Stateid4, "LOCKU result"))
            case const.OP_OPEN if value.status == const.NFS4_OK:
                self.pack_stateid(require(value.result, types.Open4Res, "OPEN result").stateid)
                self.pack_change_info(value.result.cinfo)
                self.pack_uint32(value.result.rflags)
                self.pack_bitmap(value.result.attrset)
                self.pack_delegation(value.result.delegation)
            case const.OP_OPEN_CONFIRM | const.OP_OPEN_DOWNGRADE if value.status == const.NFS4_OK:
                self.pack_stateid(require(value.result, types.Stateid4, "OPEN state result"))
            case const.OP_READ if value.status == const.NFS4_OK:
                self.pack_bool4(require(value.result, types.Read4Res, "READ result").eof)
                self.pack_opaque(value.result.data)
            case const.OP_READDIR if value.status == const.NFS4_OK:
                self.pack_fixed(require(value.result, types.ReadDir4Res, "READDIR result").cookieverf, const.NFS4_VERIFIER_SIZE, "cookie verifier")
                for entry in value.result.entries:
                    self.pack_bool4(True)
                    self.pack_entry(entry)
                self.pack_bool4(False)
                self.pack_bool4(value.result.eof)
            case const.OP_READLINK if value.status == const.NFS4_OK:
                self.pack_utf8(require(value.result, (bytes, str), "READLINK result"))
            case const.OP_REMOVE if value.status == const.NFS4_OK:
                self.pack_change_info(require(value.result, types.ChangeInfo4, "REMOVE result"))
            case const.OP_RENAME if value.status == const.NFS4_OK:
                self.pack_change_info(require(value.result, types.Rename4Res, "RENAME result").source_cinfo)
                self.pack_change_info(value.result.target_cinfo)
            case const.OP_SECINFO if value.status == const.NFS4_OK:
                self.pack_array(value.result, self.pack_secinfo)
            case const.OP_SETATTR:
                self.pack_bitmap(require(value.result, types.SetAttr4Res, "SETATTR result").attrsset)
            case const.OP_SETCLIENTID if value.status == const.NFS4_OK:
                self.pack_uint64(require(value.result, types.SetClientId4Res, "SETCLIENTID result").clientid)
                self.pack_fixed(value.result.setclientid_confirm, const.NFS4_VERIFIER_SIZE, "setclientid verifier")
            case const.OP_SETCLIENTID if value.status == const.NFS4ERR_CLID_INUSE:
                self.pack_client_addr(require(value.result, types.ClientAddr4, "client in use"))
            case const.OP_WRITE if value.status == const.NFS4_OK:
                self.pack_uint32(require(value.result, types.Write4Res, "WRITE result").count)
                self.pack_enum4(value.result.committed, {const.UNSTABLE4, const.DATA_SYNC4, const.FILE_SYNC4}, "stable_how4")
                self.pack_fixed(value.result.writeverf, const.NFS4_VERIFIER_SIZE, "write verifier")

    def pack_resop(self, value: types.ResOp4) -> None:
        self.pack_enum4(require(value, types.ResOp4, "result operation").op, const.NFS4_RESULT_OPERATIONS, "nfs_opnum4")
        self.pack_status(value.status)
        self.pack_result_data(value)

    def pack_compound_args(self, value: types.Compound4Args) -> None:
        self.pack_utf8(require(value, types.Compound4Args, "COMPOUND arguments").tag)
        if value.minorversion != const.NFS4_MINOR_VERSION:
            raise NFS4CodecError("RFC 3530 only defines minor version 0")
        self.pack_uint32(value.minorversion)
        self.pack_array(value.argarray, self.pack_argop)

    def pack_compound_res(self, value: types.Compound4Res) -> None:
        self.pack_status(require(value, types.Compound4Res, "COMPOUND result").status)
        self.pack_utf8(value.tag)
        self.pack_array(value.resarray, self.pack_resop)

    pack_COMPOUND4args = pack_compound_args
    pack_COMPOUND4res = pack_compound_res


class NFS4Unpacker(Unpacker):
    def unpack_uint32(self) -> int:
        return self.unpack_uint()

    def unpack_uint64(self) -> int:
        return self.unpack_uhyper()

    def unpack_int64(self) -> int:
        return self.unpack_hyper()

    def unpack_enum4(self, allowed: set[int] | frozenset[int], label: str) -> int:
        value = self.unpack_int()
        if value not in allowed:
            raise NFS4CodecError(f"invalid {label}: {value!r}")
        return value

    def unpack_bool4(self) -> bool:
        return bool(self.unpack_enum4({0, 1}, "bool"))

    def unpack_utf8(self) -> bytes:
        value = self.unpack_opaque()
        value.decode("utf-8")
        return value

    def unpack_opaque_limit(self, limit: int, label: str) -> bytes:
        value = self.unpack_opaque()
        if len(value) > limit:
            raise NFS4CodecError(f"{label} exceeds {limit} bytes")
        return value

    def unpack_fixed(self, length: int) -> bytes:
        return self.unpack_fopaque(length)

    def unpack_bitmap(self) -> types.Bitmap4:
        return types.Bitmap4(tuple(self.unpack_array(self.unpack_uint32)))

    def unpack_time(self) -> types.NfsTime4:
        value = types.NfsTime4(self.unpack_int64(), self.unpack_uint32())
        if value.nseconds >= 1_000_000_000:
            raise NFS4CodecError("nanoseconds must be below one second")
        return value

    def unpack_settime(self) -> types.SetTime4:
        set_it = self.unpack_enum4({const.SET_TO_SERVER_TIME4, const.SET_TO_CLIENT_TIME4}, "time_how4")
        return types.SetTime4(set_it, self.unpack_time() if set_it == const.SET_TO_CLIENT_TIME4 else None)

    def unpack_fsid(self) -> types.Fsid4:
        return types.Fsid4(self.unpack_uint64(), self.unpack_uint64())

    def unpack_pathname(self) -> tuple[bytes, ...]:
        return tuple(self.unpack_array(self.unpack_utf8))

    def unpack_fs_location(self) -> types.FsLocation4:
        return types.FsLocation4(tuple(self.unpack_array(self.unpack_utf8)), self.unpack_pathname())

    def unpack_fs_locations(self) -> types.FsLocations4:
        return types.FsLocations4(self.unpack_pathname(), tuple(self.unpack_array(self.unpack_fs_location)))

    def unpack_ace(self) -> types.NfsAce4:
        return types.NfsAce4(self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_utf8())

    def unpack_specdata(self) -> types.SpecData4:
        return types.SpecData4(self.unpack_uint32(), self.unpack_uint32())

    def unpack_stateid(self) -> types.Stateid4:
        return types.Stateid4(self.unpack_uint32(), self.unpack_fixed(const.NFS4_OTHER_SIZE))

    def unpack_change_info(self) -> types.ChangeInfo4:
        return types.ChangeInfo4(self.unpack_bool4(), self.unpack_uint64(), self.unpack_uint64())

    def unpack_client_addr(self) -> types.ClientAddr4:
        return types.ClientAddr4(self.unpack_utf8(), self.unpack_utf8())

    def unpack_callback_client(self) -> types.CallbackClient4:
        return types.CallbackClient4(self.unpack_uint32(), self.unpack_client_addr())

    def unpack_client_id(self) -> types.NfsClientId4:
        return types.NfsClientId4(self.unpack_fixed(const.NFS4_VERIFIER_SIZE), self.unpack_opaque_limit(const.NFS4_OPAQUE_LIMIT, "client id"))

    def unpack_open_owner(self) -> types.OpenOwner4:
        return types.OpenOwner4(self.unpack_uint64(), self.unpack_opaque_limit(const.NFS4_OPAQUE_LIMIT, "open owner"))

    def unpack_lock_owner(self) -> types.LockOwner4:
        return types.LockOwner4(self.unpack_uint64(), self.unpack_opaque_limit(const.NFS4_OPAQUE_LIMIT, "lock owner"))

    def unpack_attribute(self, number: int) -> Any:
        if number == const.FATTR4_SUPPORTED_ATTRS:
            return self.unpack_bitmap()
        if number == const.FATTR4_TYPE:
            return self.unpack_enum4(set(const.NFS_FTYPE4), "nfs_ftype4")
        if number in {
            const.FATTR4_FH_EXPIRE_TYPE,
            const.FATTR4_LEASE_TIME,
            const.FATTR4_ACLSUPPORT,
            const.FATTR4_MAXLINK,
            const.FATTR4_MAXNAME,
            const.FATTR4_MODE,
            const.FATTR4_NUMLINKS,
        }:
            return self.unpack_uint32()
        if number in {
            const.FATTR4_CHANGE,
            const.FATTR4_SIZE,
            const.FATTR4_FILEID,
            const.FATTR4_FILES_AVAIL,
            const.FATTR4_FILES_FREE,
            const.FATTR4_FILES_TOTAL,
            const.FATTR4_MAXFILESIZE,
            const.FATTR4_MAXREAD,
            const.FATTR4_MAXWRITE,
            const.FATTR4_QUOTA_AVAIL_HARD,
            const.FATTR4_QUOTA_AVAIL_SOFT,
            const.FATTR4_QUOTA_USED,
            const.FATTR4_SPACE_AVAIL,
            const.FATTR4_SPACE_FREE,
            const.FATTR4_SPACE_TOTAL,
            const.FATTR4_SPACE_USED,
            const.FATTR4_MOUNTED_ON_FILEID,
        }:
            return self.unpack_uint64()
        if number in {
            const.FATTR4_LINK_SUPPORT,
            const.FATTR4_SYMLINK_SUPPORT,
            const.FATTR4_NAMED_ATTR,
            const.FATTR4_UNIQUE_HANDLES,
            const.FATTR4_ARCHIVE,
            const.FATTR4_CANSETTIME,
            const.FATTR4_CASE_INSENSITIVE,
            const.FATTR4_CASE_PRESERVING,
            const.FATTR4_CHOWN_RESTRICTED,
            const.FATTR4_HIDDEN,
            const.FATTR4_HOMOGENEOUS,
            const.FATTR4_NO_TRUNC,
            const.FATTR4_SYSTEM,
        }:
            return self.unpack_bool4()
        if number == const.FATTR4_FSID:
            return self.unpack_fsid()
        if number == const.FATTR4_RDATTR_ERROR:
            return self.unpack_status()
        if number == const.FATTR4_ACL:
            return tuple(self.unpack_array(self.unpack_ace))
        if number == const.FATTR4_FILEHANDLE:
            return self.unpack_opaque_limit(const.NFS4_FHSIZE, "filehandle")
        if number == const.FATTR4_FS_LOCATIONS:
            return self.unpack_fs_locations()
        if number in {const.FATTR4_MIMETYPE, const.FATTR4_OWNER, const.FATTR4_OWNER_GROUP}:
            return self.unpack_utf8()
        if number == const.FATTR4_RAWDEV:
            return self.unpack_specdata()
        if number in {
            const.FATTR4_TIME_ACCESS,
            const.FATTR4_TIME_BACKUP,
            const.FATTR4_TIME_CREATE,
            const.FATTR4_TIME_DELTA,
            const.FATTR4_TIME_METADATA,
            const.FATTR4_TIME_MODIFY,
        }:
            return self.unpack_time()
        if number in {const.FATTR4_TIME_ACCESS_SET, const.FATTR4_TIME_MODIFY_SET}:
            return self.unpack_settime()
        raise NFS4CodecError(f"attribute {number} is not defined by RFC 3530")

    def unpack_fattr(self) -> types.Fattr4:
        attrmask = self.unpack_bitmap()
        attr_unpacker = NFS4Unpacker(self.unpack_opaque())
        attributes = {number: attr_unpacker.unpack_attribute(number) for number in attrmask.bits()}
        attr_unpacker.done()
        return types.Fattr4(attributes)

    def unpack_create_type(self) -> types.CreateType4:
        objtype = self.unpack_enum4(set(const.NFS_FTYPE4), "nfs_ftype4")
        if objtype == const.NF4LNK:
            return types.CreateType4(objtype, linkdata=self.unpack_utf8())
        if objtype in {const.NF4BLK, const.NF4CHR}:
            return types.CreateType4(objtype, devdata=self.unpack_specdata())
        return types.CreateType4(objtype)

    def unpack_open_to_lock_owner(self) -> types.OpenToLockOwner4:
        return types.OpenToLockOwner4(self.unpack_uint32(), self.unpack_stateid(), self.unpack_uint32(), self.unpack_lock_owner())

    def unpack_existing_lock_owner(self) -> types.ExistingLockOwner4:
        return types.ExistingLockOwner4(self.unpack_stateid(), self.unpack_uint32())

    def unpack_locker(self) -> types.Locker4:
        new_lock_owner = self.unpack_bool4()
        if new_lock_owner:
            return types.Locker4(True, open_owner=self.unpack_open_to_lock_owner())
        return types.Locker4(False, lock_owner=self.unpack_existing_lock_owner())

    def unpack_lock_denied(self) -> types.LockDenied4:
        return types.LockDenied4(self.unpack_uint64(), self.unpack_uint64(), self.unpack_lock_type(), self.unpack_lock_owner())

    def unpack_create_how(self) -> types.CreateHow4:
        mode = self.unpack_enum4({const.UNCHECKED4, const.GUARDED4, const.EXCLUSIVE4}, "createmode4")
        if mode in {const.UNCHECKED4, const.GUARDED4}:
            return types.CreateHow4(mode, createattrs=self.unpack_fattr())
        return types.CreateHow4(mode, createverf=self.unpack_fixed(const.NFS4_VERIFIER_SIZE))

    def unpack_open_flag(self) -> types.OpenFlag4:
        opentype = self.unpack_enum4({const.OPEN4_NOCREATE, const.OPEN4_CREATE}, "opentype4")
        return types.OpenFlag4(opentype, self.unpack_create_how() if opentype == const.OPEN4_CREATE else None)

    def unpack_space_limit(self) -> types.NfsSpaceLimit4:
        limitby = self.unpack_enum4({const.NFS_LIMIT_SIZE, const.NFS_LIMIT_BLOCKS}, "limit_by4")
        if limitby == const.NFS_LIMIT_SIZE:
            return types.NfsSpaceLimit4(limitby, filesize=self.unpack_uint64())
        return types.NfsSpaceLimit4(limitby, mod_blocks=types.NfsModifiedLimit4(self.unpack_uint32(), self.unpack_uint32()))

    def unpack_open_claim(self) -> types.OpenClaim4:
        claim = self.unpack_enum4(
            {
                const.CLAIM_NULL,
                const.CLAIM_PREVIOUS,
                const.CLAIM_DELEGATE_CUR,
                const.CLAIM_DELEGATE_PREV,
            },
            "open_claim_type4",
        )
        if claim == const.CLAIM_NULL:
            return types.OpenClaim4(claim, file=self.unpack_utf8())
        if claim == const.CLAIM_PREVIOUS:
            return types.OpenClaim4(claim, delegate_type=self.unpack_delegation_type())
        if claim == const.CLAIM_DELEGATE_CUR:
            return types.OpenClaim4(claim, delegate_cur_info=types.OpenClaimDelegateCur4(self.unpack_stateid(), self.unpack_utf8()))
        return types.OpenClaim4(claim, file_delegate_prev=self.unpack_utf8())

    def unpack_delegation(self) -> types.OpenDelegation4:
        delegation_type = self.unpack_delegation_type()
        if delegation_type == const.OPEN_DELEGATE_READ:
            return types.OpenDelegation4(delegation_type, read=types.OpenReadDelegation4(self.unpack_stateid(), self.unpack_bool4(), self.unpack_ace()))
        if delegation_type == const.OPEN_DELEGATE_WRITE:
            return types.OpenDelegation4(
                delegation_type, write=types.OpenWriteDelegation4(self.unpack_stateid(), self.unpack_bool4(), self.unpack_space_limit(), self.unpack_ace())
            )
        return types.OpenDelegation4()

    def unpack_delegation_type(self) -> int:
        return self.unpack_enum4(
            {
                const.OPEN_DELEGATE_NONE,
                const.OPEN_DELEGATE_READ,
                const.OPEN_DELEGATE_WRITE,
            },
            "open_delegation_type4",
        )

    def unpack_lock_type(self) -> int:
        return self.unpack_enum4({const.READ_LT, const.WRITE_LT, const.READW_LT, const.WRITEW_LT}, "nfs_lock_type4")

    def unpack_status(self) -> int:
        return self.unpack_enum4(set(const.NFSSTAT4), "nfsstat4")

    def unpack_secinfo(self) -> types.SecInfo4:
        flavor = self.unpack_uint32()
        if flavor == const.RPCSEC_GSS:
            return types.SecInfo4(
                flavor,
                types.RpcSecGssInfo4(
                    self.unpack_opaque(),
                    self.unpack_uint32(),
                    self.unpack_enum4(
                        {
                            const.RPC_GSS_SVC_NONE,
                            const.RPC_GSS_SVC_INTEGRITY,
                            const.RPC_GSS_SVC_PRIVACY,
                        },
                        "rpc_gss_svc_t",
                    ),
                ),
            )
        return types.SecInfo4(flavor)

    def unpack_entry(self) -> types.Entry4:
        return types.Entry4(self.unpack_uint64(), self.unpack_utf8(), self.unpack_fattr())

    def unpack_argop(self) -> types.ArgOp4:
        op = self.unpack_enum4(const.NFS4_OPERATIONS, "nfs_opnum4")
        match op:
            case const.OP_ACCESS:
                return types.ArgOp4(op, types.Access4Args(self.unpack_uint32()))
            case const.OP_CLOSE:
                return types.ArgOp4(op, types.Close4Args(self.unpack_uint32(), self.unpack_stateid()))
            case const.OP_COMMIT:
                return types.ArgOp4(op, types.Commit4Args(self.unpack_uint64(), self.unpack_uint32()))
            case const.OP_CREATE:
                return types.ArgOp4(op, types.Create4Args(self.unpack_create_type(), self.unpack_utf8(), self.unpack_fattr()))
            case const.OP_DELEGPURGE:
                return types.ArgOp4(op, types.DelegPurge4Args(self.unpack_uint64()))
            case const.OP_DELEGRETURN:
                return types.ArgOp4(op, types.DelegReturn4Args(self.unpack_stateid()))
            case const.OP_GETATTR:
                return types.ArgOp4(op, types.GetAttr4Args(self.unpack_bitmap()))
            case const.OP_LINK:
                return types.ArgOp4(op, types.Link4Args(self.unpack_utf8()))
            case const.OP_LOCK:
                return types.ArgOp4(
                    op, types.Lock4Args(self.unpack_lock_type(), self.unpack_bool4(), self.unpack_uint64(), self.unpack_uint64(), self.unpack_locker())
                )
            case const.OP_LOCKT:
                return types.ArgOp4(op, types.LockT4Args(self.unpack_lock_type(), self.unpack_uint64(), self.unpack_uint64(), self.unpack_lock_owner()))
            case const.OP_LOCKU:
                return types.ArgOp4(
                    op, types.LockU4Args(self.unpack_lock_type(), self.unpack_uint32(), self.unpack_stateid(), self.unpack_uint64(), self.unpack_uint64())
                )
            case const.OP_LOOKUP:
                return types.ArgOp4(op, types.Lookup4Args(self.unpack_utf8()))
            case const.OP_NVERIFY:
                return types.ArgOp4(op, types.NVerify4Args(self.unpack_fattr()))
            case const.OP_OPEN:
                return types.ArgOp4(
                    op,
                    types.Open4Args(
                        self.unpack_uint32(),
                        self.unpack_uint32(),
                        self.unpack_uint32(),
                        self.unpack_open_owner(),
                        self.unpack_open_flag(),
                        self.unpack_open_claim(),
                    ),
                )
            case const.OP_OPENATTR:
                return types.ArgOp4(op, types.OpenAttr4Args(self.unpack_bool4()))
            case const.OP_OPEN_CONFIRM:
                return types.ArgOp4(op, types.OpenConfirm4Args(self.unpack_stateid(), self.unpack_uint32()))
            case const.OP_OPEN_DOWNGRADE:
                return types.ArgOp4(op, types.OpenDowngrade4Args(self.unpack_stateid(), self.unpack_uint32(), self.unpack_uint32(), self.unpack_uint32()))
            case const.OP_PUTFH:
                return types.ArgOp4(op, types.PutFh4Args(self.unpack_opaque_limit(const.NFS4_FHSIZE, "filehandle")))
            case const.OP_READ:
                return types.ArgOp4(op, types.Read4Args(self.unpack_stateid(), self.unpack_uint64(), self.unpack_uint32()))
            case const.OP_READDIR:
                return types.ArgOp4(
                    op,
                    types.ReadDir4Args(
                        self.unpack_uint64(), self.unpack_fixed(const.NFS4_VERIFIER_SIZE), self.unpack_uint32(), self.unpack_uint32(), self.unpack_bitmap()
                    ),
                )
            case const.OP_REMOVE:
                return types.ArgOp4(op, types.Remove4Args(self.unpack_utf8()))
            case const.OP_RENAME:
                return types.ArgOp4(op, types.Rename4Args(self.unpack_utf8(), self.unpack_utf8()))
            case const.OP_RENEW:
                return types.ArgOp4(op, types.Renew4Args(self.unpack_uint64()))
            case const.OP_SECINFO:
                return types.ArgOp4(op, types.SecInfo4Args(self.unpack_utf8()))
            case const.OP_SETATTR:
                return types.ArgOp4(op, types.SetAttr4Args(self.unpack_stateid(), self.unpack_fattr()))
            case const.OP_SETCLIENTID:
                return types.ArgOp4(op, types.SetClientId4Args(self.unpack_client_id(), self.unpack_callback_client(), self.unpack_uint32()))
            case const.OP_SETCLIENTID_CONFIRM:
                return types.ArgOp4(op, types.SetClientIdConfirm4Args(self.unpack_uint64(), self.unpack_fixed(const.NFS4_VERIFIER_SIZE)))
            case const.OP_VERIFY:
                return types.ArgOp4(op, types.Verify4Args(self.unpack_fattr()))
            case const.OP_WRITE:
                return types.ArgOp4(
                    op,
                    types.Write4Args(
                        self.unpack_stateid(),
                        self.unpack_uint64(),
                        self.unpack_enum4({const.UNSTABLE4, const.DATA_SYNC4, const.FILE_SYNC4}, "stable_how4"),
                        self.unpack_opaque(),
                    ),
                )
            case const.OP_RELEASE_LOCKOWNER:
                return types.ArgOp4(op, types.ReleaseLockOwner4Args(self.unpack_lock_owner()))
            case _:
                return types.ArgOp4(op)

    def unpack_result_data(self, op: int, status: int) -> Any:
        match op:
            case const.OP_ACCESS if status == const.NFS4_OK:
                return types.Access4Res(self.unpack_uint32(), self.unpack_uint32())
            case const.OP_CLOSE if status == const.NFS4_OK:
                return self.unpack_stateid()
            case const.OP_COMMIT if status == const.NFS4_OK:
                return types.Commit4Res(self.unpack_fixed(const.NFS4_VERIFIER_SIZE))
            case const.OP_CREATE if status == const.NFS4_OK:
                return types.Create4Res(self.unpack_change_info(), self.unpack_bitmap())
            case const.OP_GETATTR if status == const.NFS4_OK:
                return self.unpack_fattr()
            case const.OP_GETFH if status == const.NFS4_OK:
                return self.unpack_opaque_limit(const.NFS4_FHSIZE, "filehandle")
            case const.OP_LINK if status == const.NFS4_OK:
                return types.Link4Res(self.unpack_change_info())
            case const.OP_LOCK if status == const.NFS4_OK:
                return self.unpack_stateid()
            case const.OP_LOCK | const.OP_LOCKT if status == const.NFS4ERR_DENIED:
                return self.unpack_lock_denied()
            case const.OP_LOCKU if status == const.NFS4_OK:
                return self.unpack_stateid()
            case const.OP_OPEN if status == const.NFS4_OK:
                return types.Open4Res(self.unpack_stateid(), self.unpack_change_info(), self.unpack_uint32(), self.unpack_bitmap(), self.unpack_delegation())
            case const.OP_OPEN_CONFIRM | const.OP_OPEN_DOWNGRADE if status == const.NFS4_OK:
                return self.unpack_stateid()
            case const.OP_READ if status == const.NFS4_OK:
                return types.Read4Res(self.unpack_bool4(), self.unpack_opaque())
            case const.OP_READDIR if status == const.NFS4_OK:
                cookieverf = self.unpack_fixed(const.NFS4_VERIFIER_SIZE)
                entries = []
                while self.unpack_bool4():
                    entries.append(self.unpack_entry())
                return types.ReadDir4Res(cookieverf, tuple(entries), self.unpack_bool4())
            case const.OP_READLINK if status == const.NFS4_OK:
                return self.unpack_utf8()
            case const.OP_REMOVE if status == const.NFS4_OK:
                return self.unpack_change_info()
            case const.OP_RENAME if status == const.NFS4_OK:
                return types.Rename4Res(self.unpack_change_info(), self.unpack_change_info())
            case const.OP_SECINFO if status == const.NFS4_OK:
                return tuple(self.unpack_array(self.unpack_secinfo))
            case const.OP_SETATTR:
                return types.SetAttr4Res(self.unpack_bitmap())
            case const.OP_SETCLIENTID if status == const.NFS4_OK:
                return types.SetClientId4Res(self.unpack_uint64(), self.unpack_fixed(const.NFS4_VERIFIER_SIZE))
            case const.OP_SETCLIENTID if status == const.NFS4ERR_CLID_INUSE:
                return self.unpack_client_addr()
            case const.OP_WRITE if status == const.NFS4_OK:
                return types.Write4Res(
                    self.unpack_uint32(),
                    self.unpack_enum4({const.UNSTABLE4, const.DATA_SYNC4, const.FILE_SYNC4}, "stable_how4"),
                    self.unpack_fixed(const.NFS4_VERIFIER_SIZE),
                )
            case _:
                return None

    def unpack_resop(self) -> types.ResOp4:
        op = self.unpack_enum4(const.NFS4_RESULT_OPERATIONS, "nfs_opnum4")
        status = self.unpack_status()
        return types.ResOp4(op, status, self.unpack_result_data(op, status))

    def unpack_compound_args(self) -> types.Compound4Args:
        tag = self.unpack_utf8()
        minorversion = self.unpack_uint32()
        if minorversion != const.NFS4_MINOR_VERSION:
            raise NFS4CodecError("RFC 3530 only defines minor version 0")
        return types.Compound4Args(tag, minorversion, tuple(self.unpack_array(self.unpack_argop)))

    def unpack_compound_res(self) -> types.Compound4Res:
        return types.Compound4Res(self.unpack_status(), self.unpack_utf8(), tuple(self.unpack_array(self.unpack_resop)))

    unpack_COMPOUND4args = unpack_compound_args
    unpack_COMPOUND4res = unpack_compound_res


nfs_pro_v4Packer = NFS4Packer
nfs_pro_v4Unpacker = NFS4Unpacker
