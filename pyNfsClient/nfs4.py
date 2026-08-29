"""Raw NFSv4.0 client for the RFC 3530 forechannel."""

import logging
import os
import secrets
import socket
from dataclasses import dataclass

from . import const as v3
from . import nfs4_const as const
from . import nfs4_types as types
from .nfs3 import fh_check
from .nfs4_pack import NFS4Packer, NFS4Unpacker
from .rpc import RPC
from .utils import str_to_bytes

DEFAULT_ATTRIBUTES = types.Bitmap4.from_bits(
    const.FATTR4_TYPE,
    const.FATTR4_SIZE,
    const.FATTR4_FSID,
    const.FATTR4_FILEID,
    const.FATTR4_MODE,
    const.FATTR4_NUMLINKS,
    const.FATTR4_OWNER,
    const.FATTR4_OWNER_GROUP,
    const.FATTR4_RAWDEV,
    const.FATTR4_SPACE_USED,
    const.FATTR4_TIME_ACCESS,
    const.FATTR4_TIME_METADATA,
    const.FATTR4_TIME_MODIFY,
)
DIRECTORY_ATTRIBUTES = types.Bitmap4.from_bits(*DEFAULT_ATTRIBUTES.bits(), const.FATTR4_FILEHANDLE, const.FATTR4_RDATTR_ERROR)
READDIR_ATTRIBUTES = types.Bitmap4.from_bits(const.FATTR4_FILEID)
FILESYSTEM_ATTRIBUTES = types.Bitmap4.from_bits(
    *DEFAULT_ATTRIBUTES.bits(),
    const.FATTR4_FILES_AVAIL,
    const.FATTR4_FILES_FREE,
    const.FATTR4_FILES_TOTAL,
    const.FATTR4_MAXFILESIZE,
    const.FATTR4_MAXNAME,
    const.FATTR4_MAXREAD,
    const.FATTR4_MAXWRITE,
    const.FATTR4_SPACE_AVAIL,
    const.FATTR4_SPACE_FREE,
    const.FATTR4_SPACE_TOTAL,
)
FSINFO_ATTRIBUTES = types.Bitmap4.from_bits(
    *DEFAULT_ATTRIBUTES.bits(),
    const.FATTR4_CANSETTIME,
    const.FATTR4_HOMOGENEOUS,
    const.FATTR4_LINK_SUPPORT,
    const.FATTR4_SYMLINK_SUPPORT,
    const.FATTR4_MAXFILESIZE,
    const.FATTR4_MAXREAD,
    const.FATTR4_MAXWRITE,
    const.FATTR4_TIME_DELTA,
)
PATHCONF_ATTRIBUTES = types.Bitmap4.from_bits(
    *DEFAULT_ATTRIBUTES.bits(),
    const.FATTR4_MAXLINK,
    const.FATTR4_MAXNAME,
    const.FATTR4_NO_TRUNC,
    const.FATTR4_CHOWN_RESTRICTED,
    const.FATTR4_CASE_INSENSITIVE,
    const.FATTR4_CASE_PRESERVING,
)
SEQUENCE_RETRY_STATUSES = frozenset(
    {
        const.NFS4ERR_STALE_CLIENTID,
        const.NFS4ERR_STALE_STATEID,
        const.NFS4ERR_BAD_STATEID,
        const.NFS4ERR_BAD_SEQID,
        const.NFS4ERR_BADXDR,
        const.NFS4ERR_RESOURCE,
        const.NFS4ERR_NOFILEHANDLE,
    }
)
logger = logging.getLogger(__package__)


def nfs3_identity(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return int(value) if isinstance(value, str) and value.isdecimal() else value


def nfs3_time(value=None):
    return {
        "seconds": 0 if value is None else value.seconds,
        "nseconds": 0 if value is None else value.nseconds,
    }


def nfs3_attributes(attributes):
    values = attributes.attributes
    rawdev = values.get(const.FATTR4_RAWDEV, types.SpecData4(0, 0))
    fsid = values.get(const.FATTR4_FSID, types.Fsid4(0, 0))
    return {
        "type": values.get(const.FATTR4_TYPE, const.NF4REG),
        "mode": values.get(const.FATTR4_MODE, 0),
        "nlink": values.get(const.FATTR4_NUMLINKS, 1),
        "uid": nfs3_identity(values.get(const.FATTR4_OWNER, 0)),
        "gid": nfs3_identity(values.get(const.FATTR4_OWNER_GROUP, 0)),
        "size": values.get(const.FATTR4_SIZE, 0),
        "used": values.get(const.FATTR4_SPACE_USED, values.get(const.FATTR4_SIZE, 0)),
        "rdev": {"major": rawdev.specdata1, "minor": rawdev.specdata2},
        "fsid": fsid.major << 64 | fsid.minor,
        "fileid": values.get(const.FATTR4_FILEID, 0),
        "atime": nfs3_time(values.get(const.FATTR4_TIME_ACCESS)),
        "mtime": nfs3_time(values.get(const.FATTR4_TIME_MODIFY)),
        "ctime": nfs3_time(values.get(const.FATTR4_TIME_METADATA)),
    }


def post_op_attributes(attributes=None):
    if attributes is not None and attributes.attributes.get(const.FATTR4_RDATTR_ERROR, const.NFS4_OK) != const.NFS4_OK:
        attributes = None
    return {
        "present": attributes is not None,
        "attributes": None if attributes is None else nfs3_attributes(attributes),
    }


def wcc_data(attributes=None, before=None):
    return {
        "before": {
            "present": before is not None,
            "attributes": None
            if before is None
            else {
                "size": nfs3_attributes(before)["size"],
                "mtime": nfs3_attributes(before)["mtime"],
                "ctime": nfs3_attributes(before)["ctime"],
            },
        },
        "after": post_op_attributes(attributes),
    }


def post_op_handle(filehandle=None):
    return {
        "present": filehandle is not None,
        "handle": None if filehandle is None else {"data": filehandle},
    }


def linked_entries(entries, include_attributes):
    linked = []
    for entry in reversed(entries):
        values = entry.attrs.attributes
        item = {
            "fileid": values.get(const.FATTR4_FILEID, 0),
            "name": str_to_bytes(entry.name),
            "cookie": entry.cookie,
            "nextentry": linked,
        }
        if include_attributes:
            item["name_attributes"] = post_op_attributes(entry.attrs)
            item["name_handle"] = post_op_handle(values.get(const.FATTR4_FILEHANDLE))
        linked = [item]
    return linked


def nfs4_settime(flag, seconds, nseconds):
    if flag == v3.DONT_CHANGE:
        return None
    if flag == v3.SET_TO_SERVER_TIME:
        return types.SetTime4(const.SET_TO_SERVER_TIME4)
    if flag == v3.SET_TO_CLIENT_TIME:
        return types.SetTime4(const.SET_TO_CLIENT_TIME4, types.NfsTime4(0 if seconds is None else seconds, 0 if nseconds is None else nseconds))
    raise ValueError(f"time flag must be one of {tuple(v3.time_how)}")


def nfs4_attributes(
    mode=None,
    uid=None,
    gid=None,
    size=None,
    atime_flag=v3.SET_TO_SERVER_TIME,
    atime_s=None,
    atime_ns=None,
    mtime_flag=v3.SET_TO_SERVER_TIME,
    mtime_s=None,
    mtime_ns=None,
):
    attributes = {}
    if mode is not None:
        attributes[const.FATTR4_MODE] = int(mode)
    if uid is not None:
        attributes[const.FATTR4_OWNER] = str(uid)
    if gid is not None:
        attributes[const.FATTR4_OWNER_GROUP] = str(gid)
    if size is not None:
        attributes[const.FATTR4_SIZE] = int(size)
    if nfs4_settime(atime_flag, atime_s, atime_ns) is not None:
        attributes[const.FATTR4_TIME_ACCESS_SET] = nfs4_settime(atime_flag, atime_s, atime_ns)
    if nfs4_settime(mtime_flag, mtime_s, mtime_ns) is not None:
        attributes[const.FATTR4_TIME_MODIFY_SET] = nfs4_settime(mtime_flag, mtime_s, mtime_ns)
    return types.Fattr4(attributes)


def operation_results(response, operation):
    return tuple(result.result for result in response.resarray if result.op == operation and result.status == const.NFS4_OK)


def operation_status(response, operation, occurrence=0):
    for result in response.resarray:
        if result.op == operation:
            if occurrence == 0:
                return result.status
            occurrence -= 1
    return response.status


def response_failure(status, failure):
    return {"status": status, "resok": None, "resfail": failure}


def wcc_failure(status, failure):
    return {"status": status, "resfail": failure}


def verifier8(value):
    return str_to_bytes(value).ljust(const.NFS4_VERIFIER_SIZE, b"\0")[: const.NFS4_VERIFIER_SIZE]


class NFS4Error(Exception):
    """An NFSv4 operation returned a non-success status."""

    def __init__(self, status, operation=None, index=None, response=None):
        self.status = status
        self.operation = operation
        self.index = index
        self.response = response
        super().__init__(self.message())

    def message(self):
        if self.operation is None:
            return const.NFSSTAT4.get(self.status, f"NFSv4 status {self.status}")
        return f"{const.NFS_OPNUM4.get(self.operation, f'operation {self.operation}')} failed with {const.NFSSTAT4.get(self.status, self.status)}"


@dataclass(frozen=True, slots=True)
class OpenFile4:
    filehandle: bytes
    stateid: types.Stateid4
    share_access: int
    share_deny: int


@dataclass(frozen=True, slots=True)
class LockedFile4:
    filehandle: bytes
    stateid: types.Stateid4
    owner: types.LockOwner4
    seqid: int = 1


class NFSv4(RPC):
    """NFSv4.0 client which connects directly to the server's NFS port."""

    def __init__(self, host, port=2049, timeout=5, auth=None):
        super().__init__(host, port, timeout)
        self.auth = auth
        self.clientid = None
        self.client_name = None
        self.client_name_nonce = secrets.token_hex(8)
        self.client_verifier = None
        self.open_owner = None
        self.open_seqid = 0
        self.locations = {}
        self.opened = {}
        self.lock_seqids = {}

    def nfs_request(self, procedure, args, auth):
        return super().request(const.NFS_PROGRAM, const.NFS_V4, procedure, data=args, auth=self.auth if auth is None else auth)

    def null(self):
        self.nfs_request(const.NFS4_PROCEDURE_NULL, b"", self.auth)
        return {"status": const.NFS4_OK, "resok": None}

    def compound(self, operations, tag=b"", auth=None, check=True):
        operations = tuple(operations)
        packer = NFS4Packer()
        packer.pack_compound_args(types.Compound4Args(tag=tag, argarray=operations))
        unpacker = NFS4Unpacker(self.nfs_request(const.NFS4_PROCEDURE_COMPOUND, packer.get_buffer(), self.auth if auth is None else auth))
        response = unpacker.unpack_compound_res()
        unpacker.done()
        self.check_response(operations, response, check)
        return response

    @staticmethod
    def check_response(operations, response, check=True):
        if len(response.resarray) > len(operations):
            raise NFS4Error(const.NFS4ERR_BADXDR, response=response)
        for index, result in enumerate(response.resarray):
            if result.op != operations[index].op:
                raise NFS4Error(const.NFS4ERR_BADXDR, result.op, index, response)
            if result.status != const.NFS4_OK and index != len(response.resarray) - 1:
                raise NFS4Error(const.NFS4ERR_BADXDR, result.op, index, response)
        if response.resarray and response.status != response.resarray[-1].status:
            raise NFS4Error(const.NFS4ERR_BADXDR, response=response)
        if response.status == const.NFS4_OK and len(response.resarray) != len(operations):
            raise NFS4Error(const.NFS4ERR_BADXDR, response=response)
        if check and response.status != const.NFS4_OK:
            if response.resarray:
                raise NFS4Error(response.status, response.resarray[-1].op, len(response.resarray) - 1, response)
            raise NFS4Error(response.status, response=response)

    @staticmethod
    def operation_result(response, operation, occurrence=0):
        for result in response.resarray:
            if result.op == operation:
                if occurrence == 0:
                    return result.result
                occurrence -= 1
        raise ValueError(f"response does not contain {const.NFS_OPNUM4.get(operation, operation)}")

    def with_filehandle(self, filehandle, *operations, tag=b"", auth=None, check=True):
        return self.compound((self.putfh_op(filehandle), *operations), tag, auth, check)

    def with_root(self, *operations, tag=b"", auth=None, check=True):
        return self.compound((self.putrootfh_op(), *operations), tag, auth, check)

    def with_public(self, *operations, tag=b"", auth=None, check=True):
        return self.compound((self.putpubfh_op(), *operations), tag, auth, check)

    def with_filehandles(self, current_filehandle, saved_filehandle, *operations, tag=b"", auth=None, check=True):
        return self.compound(
            (
                self.putfh_op(saved_filehandle),
                self.savefh_op(),
                self.putfh_op(current_filehandle),
                *operations,
            ),
            tag,
            auth,
            check,
        )

    def sequenced_filehandle(self, filehandle, operation, *operations, tag=b"", auth=None):
        try:
            response = self.with_filehandle(filehandle, operation, *operations, tag=tag, auth=auth)
        except NFS4Error as e:
            if e.index is not None and (e.index > 1 or e.index == 1 and e.status not in SEQUENCE_RETRY_STATUSES):
                self.open_seqid = (self.open_seqid + 1) & 0xFFFFFFFF
            raise
        self.open_seqid = (self.open_seqid + 1) & 0xFFFFFFFF
        return response

    @staticmethod
    def access_op(access):
        return types.ArgOp4(const.OP_ACCESS, types.Access4Args(access))

    @staticmethod
    def close_op(seqid, open_stateid):
        return types.ArgOp4(const.OP_CLOSE, types.Close4Args(seqid, open_stateid))

    @staticmethod
    def commit_op(offset=0, count=0):
        return types.ArgOp4(const.OP_COMMIT, types.Commit4Args(offset, count))

    @staticmethod
    def create_op(objtype, objname, createattrs=types.Fattr4()):
        return types.ArgOp4(const.OP_CREATE, types.Create4Args(objtype, objname, createattrs))

    @staticmethod
    def delegpurge_op(clientid):
        return types.ArgOp4(const.OP_DELEGPURGE, types.DelegPurge4Args(clientid))

    @staticmethod
    def delegreturn_op(deleg_stateid):
        return types.ArgOp4(const.OP_DELEGRETURN, types.DelegReturn4Args(deleg_stateid))

    @staticmethod
    def getattr_op(attr_request=DEFAULT_ATTRIBUTES):
        return types.ArgOp4(const.OP_GETATTR, types.GetAttr4Args(attr_request))

    @staticmethod
    def getfh_op():
        return types.ArgOp4(const.OP_GETFH)

    @staticmethod
    def link_op(newname):
        return types.ArgOp4(const.OP_LINK, types.Link4Args(newname))

    @staticmethod
    def lock_op(locktype, reclaim, offset, length, locker):
        return types.ArgOp4(const.OP_LOCK, types.Lock4Args(locktype, reclaim, offset, length, locker))

    @staticmethod
    def lockt_op(locktype, offset, length, owner):
        return types.ArgOp4(const.OP_LOCKT, types.LockT4Args(locktype, offset, length, owner))

    @staticmethod
    def locku_op(locktype, seqid, lock_stateid, offset, length):
        return types.ArgOp4(const.OP_LOCKU, types.LockU4Args(locktype, seqid, lock_stateid, offset, length))

    @staticmethod
    def lookup_op(objname):
        return types.ArgOp4(const.OP_LOOKUP, types.Lookup4Args(objname))

    @staticmethod
    def lookupp_op():
        return types.ArgOp4(const.OP_LOOKUPP)

    @staticmethod
    def nverify_op(obj_attributes):
        return types.ArgOp4(const.OP_NVERIFY, types.NVerify4Args(obj_attributes))

    @staticmethod
    def open_op(seqid, share_access, share_deny, owner, openhow, claim):
        return types.ArgOp4(const.OP_OPEN, types.Open4Args(seqid, share_access, share_deny, owner, openhow, claim))

    @staticmethod
    def openattr_op(createdir=False):
        return types.ArgOp4(const.OP_OPENATTR, types.OpenAttr4Args(createdir))

    @staticmethod
    def open_confirm_op(open_stateid, seqid):
        return types.ArgOp4(const.OP_OPEN_CONFIRM, types.OpenConfirm4Args(open_stateid, seqid))

    @staticmethod
    def open_downgrade_op(open_stateid, seqid, share_access, share_deny):
        return types.ArgOp4(const.OP_OPEN_DOWNGRADE, types.OpenDowngrade4Args(open_stateid, seqid, share_access, share_deny))

    @staticmethod
    def putfh_op(filehandle):
        return types.ArgOp4(const.OP_PUTFH, types.PutFh4Args(filehandle))

    @staticmethod
    def putpubfh_op():
        return types.ArgOp4(const.OP_PUTPUBFH)

    @staticmethod
    def putrootfh_op():
        return types.ArgOp4(const.OP_PUTROOTFH)

    @staticmethod
    def read_op(stateid, offset=0, count=1024 * 1024):
        return types.ArgOp4(const.OP_READ, types.Read4Args(stateid, offset, count))

    @staticmethod
    def readdir_op(cookie=0, cookieverf=b"\0" * const.NFS4_VERIFIER_SIZE, dircount=32 * 1024, maxcount=64 * 1024, attr_request=DIRECTORY_ATTRIBUTES):
        return types.ArgOp4(const.OP_READDIR, types.ReadDir4Args(cookie, cookieverf, dircount, maxcount, attr_request))

    @staticmethod
    def readlink_op():
        return types.ArgOp4(const.OP_READLINK)

    @staticmethod
    def remove_op(target):
        return types.ArgOp4(const.OP_REMOVE, types.Remove4Args(target))

    @staticmethod
    def rename_op(oldname, newname):
        return types.ArgOp4(const.OP_RENAME, types.Rename4Args(oldname, newname))

    @staticmethod
    def renew_op(clientid):
        return types.ArgOp4(const.OP_RENEW, types.Renew4Args(clientid))

    @staticmethod
    def restorefh_op():
        return types.ArgOp4(const.OP_RESTOREFH)

    @staticmethod
    def savefh_op():
        return types.ArgOp4(const.OP_SAVEFH)

    @staticmethod
    def secinfo_op(name):
        return types.ArgOp4(const.OP_SECINFO, types.SecInfo4Args(name))

    @staticmethod
    def setattr_op(stateid, obj_attributes):
        return types.ArgOp4(const.OP_SETATTR, types.SetAttr4Args(stateid, obj_attributes))

    @staticmethod
    def setclientid_op(client, callback, callback_ident=0):
        return types.ArgOp4(const.OP_SETCLIENTID, types.SetClientId4Args(client, callback, callback_ident))

    @staticmethod
    def setclientid_confirm_op(clientid, setclientid_confirm):
        return types.ArgOp4(const.OP_SETCLIENTID_CONFIRM, types.SetClientIdConfirm4Args(clientid, setclientid_confirm))

    @staticmethod
    def verify_op(obj_attributes):
        return types.ArgOp4(const.OP_VERIFY, types.Verify4Args(obj_attributes))

    @staticmethod
    def write_op(stateid, offset, data, stable=const.FILE_SYNC4):
        return types.ArgOp4(const.OP_WRITE, types.Write4Args(stateid, offset, stable, data))

    @staticmethod
    def release_lockowner_op(lock_owner):
        return types.ArgOp4(const.OP_RELEASE_LOCKOWNER, types.ReleaseLockOwner4Args(lock_owner))

    def establish_client(self, client_name=None, verifier=None, open_owner=None, auth=None):
        if client_name is None:
            client_name = f"{socket.gethostname()}:{os.getpid()}:{self.client_name_nonce}".encode()
        elif isinstance(client_name, str):
            client_name = client_name.encode()
        if verifier is None:
            verifier = secrets.token_bytes(const.NFS4_VERIFIER_SIZE)
        self.client_name = client_name
        self.client_verifier = verifier
        response = self.compound(
            (
                self.setclientid_op(types.NfsClientId4(verifier, client_name), types.CallbackClient4(0, types.ClientAddr4(b"", b""))),
            ),
            tag=b"setclientid",
            auth=auth,
        )
        self.clientid = self.operation_result(response, const.OP_SETCLIENTID).clientid
        self.compound(
            (
                self.setclientid_confirm_op(self.clientid, self.operation_result(response, const.OP_SETCLIENTID).setclientid_confirm),
            ),
            tag=b"setclientid-confirm",
            auth=auth,
        )
        self.open_owner = (open_owner.encode() if isinstance(open_owner, str) else open_owner) or client_name
        self.open_seqid = 0
        return self.clientid

    def require_client(self):
        if self.clientid is None or self.open_owner is None:
            raise RuntimeError("SETCLIENTID must be confirmed before using NFSv4 state")

    def open_file(
        self,
        parent_filehandle,
        name,
        share_access=const.OPEN4_SHARE_ACCESS_READ,
        share_deny=const.OPEN4_SHARE_DENY_NONE,
        openhow=types.OpenFlag4(),
        claim=None,
        auth=None,
    ):
        self.require_client()
        if claim is None:
            claim = types.OpenClaim4(const.CLAIM_NULL, file=name)
        response = self.sequenced_filehandle(
            parent_filehandle,
            self.open_op(self.open_seqid, share_access, share_deny, types.OpenOwner4(self.clientid, self.open_owner), openhow, claim),
            self.getfh_op(),
            tag=b"open",
            auth=auth,
        )
        open_result = self.operation_result(response, const.OP_OPEN)
        filehandle = self.operation_result(response, const.OP_GETFH)
        stateid = open_result.stateid
        if open_result.rflags & const.OPEN4_RESULT_CONFIRM:
            response = self.sequenced_filehandle(filehandle, self.open_confirm_op(stateid, self.open_seqid), tag=b"open-confirm", auth=auth)
            stateid = self.operation_result(response, const.OP_OPEN_CONFIRM)
        if open_result.delegation.delegation_type != const.OPEN_DELEGATE_NONE:
            self.with_filehandle(filehandle, self.delegreturn_op(self.delegation_stateid(open_result.delegation)), tag=b"delegreturn", auth=auth)
        return OpenFile4(filehandle, stateid, share_access, share_deny)

    @staticmethod
    def delegation_stateid(delegation):
        if delegation.delegation_type == const.OPEN_DELEGATE_READ:
            return delegation.read.stateid
        if delegation.delegation_type == const.OPEN_DELEGATE_WRITE:
            return delegation.write.stateid
        raise ValueError("OPEN result does not contain a delegation")

    def close_file(self, opened_file, auth=None):
        response = self.sequenced_filehandle(opened_file.filehandle, self.close_op(self.open_seqid, opened_file.stateid), tag=b"close", auth=auth)
        return self.operation_result(response, const.OP_CLOSE)

    def downgrade_file(self, opened_file, share_access, share_deny):
        response = self.sequenced_filehandle(
            opened_file.filehandle, self.open_downgrade_op(opened_file.stateid, self.open_seqid, share_access, share_deny), tag=b"open-downgrade"
        )
        return OpenFile4(opened_file.filehandle, self.operation_result(response, const.OP_OPEN_DOWNGRADE), share_access, share_deny)

    def renew_client(self):
        self.require_client()
        self.compound((self.renew_op(self.clientid),), tag=b"renew")

    def acquire_lock(self, opened_file, owner, locktype=const.WRITE_LT, offset=0, length=0xFFFFFFFFFFFFFFFF, reclaim=False):
        self.require_client()
        if isinstance(owner, str):
            owner = owner.encode()
        lock_owner = types.LockOwner4(self.clientid, owner)
        response = self.sequenced_filehandle(
            opened_file.filehandle,
            self.lock_op(
                locktype, reclaim, offset, length, types.Locker4(True, open_owner=types.OpenToLockOwner4(self.open_seqid, opened_file.stateid, 0, lock_owner))
            ),
            tag=b"lock",
        )
        return LockedFile4(opened_file.filehandle, self.operation_result(response, const.OP_LOCK), lock_owner)

    def unlock(self, locked_file, locktype=const.WRITE_LT, offset=0, length=0xFFFFFFFFFFFFFFFF):
        lock_seqid = self.lock_seqids.get(locked_file.owner, locked_file.seqid)
        try:
            response = self.with_filehandle(locked_file.filehandle, self.locku_op(locktype, lock_seqid, locked_file.stateid, offset, length), tag=b"locku")
        except NFS4Error as e:
            if e.index is not None and (e.index > 1 or e.index == 1 and e.status not in SEQUENCE_RETRY_STATUSES):
                self.lock_seqids[locked_file.owner] = (lock_seqid + 1) & 0xFFFFFFFF
            raise
        self.lock_seqids[locked_file.owner] = (lock_seqid + 1) & 0xFFFFFFFF
        return LockedFile4(locked_file.filehandle, self.operation_result(response, const.OP_LOCKU), locked_file.owner, self.lock_seqids[locked_file.owner])

    def test_lock(self, filehandle, owner, locktype=const.WRITE_LT, offset=0, length=0xFFFFFFFFFFFFFFFF):
        self.require_client()
        if isinstance(owner, str):
            owner = owner.encode()
        response = self.with_filehandle(filehandle, self.lockt_op(locktype, offset, length, types.LockOwner4(self.clientid, owner)), tag=b"lockt", check=False)
        if response.status == const.NFS4_OK:
            return None
        if response.status != const.NFS4ERR_DENIED:
            raise NFS4Error(response.status, const.OP_LOCKT, len(response.resarray) - 1, response)
        return self.operation_result(response, const.OP_LOCKT)

    def release_lock_owner(self, owner):
        self.require_client()
        if isinstance(owner, str):
            owner = owner.encode()
        lock_owner = types.LockOwner4(self.clientid, owner)
        self.compound((self.release_lockowner_op(lock_owner),), tag=b"release-lockowner")
        self.lock_seqids.pop(lock_owner, None)

    def root_filehandle(self, auth=None):
        response = self.with_root(self.getfh_op(), tag=b"rootfh", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            raise NFS4Error(response.status, response=response)
        return self.operation_result(response, const.OP_GETFH)

    def lookup_path(self, path, attr_request=DEFAULT_ATTRIBUTES, auth=None):
        response = self.compound(
            (
                self.putrootfh_op(),
                *(self.lookup_op(component) for component in path.split(b"/" if isinstance(path, bytes) else "/") if component),
                self.getfh_op(),
                self.getattr_op(attr_request),
            ),
            tag=b"lookup-path",
            auth=auth,
        )
        return (
            self.operation_result(response, const.OP_GETFH),
            self.operation_result(response, const.OP_GETATTR),
        )

    def ensure_client(self, auth=None):
        if self.clientid is None or self.open_owner is None:
            self.establish_client(auth=auth)

    def ensure_open(self, file_handle, share_access, auth=None):
        if file_handle in self.opened and self.opened[file_handle].share_access & share_access == share_access:
            return self.opened[file_handle]
        if file_handle not in self.locations:
            return OpenFile4(file_handle, types.Stateid4(), share_access, const.OPEN4_SHARE_DENY_NONE)
        self.ensure_client(auth)
        self.opened[file_handle] = self.open_file(
            *self.locations[file_handle], share_access | (self.opened[file_handle].share_access if file_handle in self.opened else 0), auth=auth
        )
        return self.opened[file_handle]

    def close_handle(self, file_handle, auth=None):
        if file_handle not in self.opened:
            return False
        self.close_file(self.opened[file_handle], auth)
        self.opened.pop(file_handle)
        return True

    def disconnect(self):
        if self.client is not None:
            for file_handle in tuple(self.opened):
                try:
                    self.close_handle(file_handle)
                except Exception as e:
                    logger.debug("Unable to close NFSv4 state for %r: %s", file_handle, e)
        self.locations.clear()
        self.opened.clear()
        self.lock_seqids.clear()
        super().disconnect()

    def get_attributes4(self, file_handle, attr_request=DEFAULT_ATTRIBUTES, auth=None):
        response = self.with_filehandle(file_handle, self.getattr_op(attr_request), tag=b"getattr", auth=auth, check=False)
        return (
            response.status,
            operation_results(response, const.OP_GETATTR)[0] if operation_results(response, const.OP_GETATTR) else None,
        )

    @fh_check
    def getattr(self, file_handle, auth=None):
        status, attributes = self.get_attributes4(file_handle, auth=auth)
        if status != const.NFS4_OK:
            return {"status": status, "attributes": None}
        return {"status": status, "attributes": nfs3_attributes(attributes)}

    @fh_check
    def setattr(
        self,
        file_handle,
        mode=None,
        uid=None,
        gid=None,
        size=None,
        atime_flag=v3.SET_TO_SERVER_TIME,
        atime_s=None,
        atime_us=None,
        mtime_flag=v3.SET_TO_SERVER_TIME,
        mtime_s=None,
        mtime_us=None,
        check=False,
        obj_ctime=None,
        auth=None,
    ):
        operations = [self.getattr_op(DEFAULT_ATTRIBUTES)]
        if check:
            operations.append(
                self.verify_op(
                    types.Fattr4(
                        {
                            const.FATTR4_TIME_METADATA: types.NfsTime4(
                                obj_ctime["seconds"] if isinstance(obj_ctime, dict) else obj_ctime.seconds,
                                obj_ctime["nseconds"] if isinstance(obj_ctime, dict) else obj_ctime.nseconds,
                            )
                        }
                    )
                )
            )
        try:
            operations.extend(
                (
                    self.setattr_op(
                        self.ensure_open(file_handle, const.OPEN4_SHARE_ACCESS_WRITE, auth).stateid if size is not None else types.Stateid4(),
                        nfs4_attributes(mode, uid, gid, size, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us),
                    ),
                    self.getattr_op(DEFAULT_ATTRIBUTES),
                )
            )
        except NFS4Error as e:
            return wcc_failure(e.status, wcc_data())
        response = self.with_filehandle(file_handle, *operations, tag=b"setattr", auth=auth, check=False)
        attributes = operation_results(response, const.OP_GETATTR)
        status = operation_status(response, const.OP_SETATTR)
        if status != const.NFS4_OK:
            return wcc_failure(status, wcc_data(before=attributes[0] if attributes else None))
        return {
            "status": status,
            "resok": wcc_data(attributes[1] if len(attributes) > 1 else None, attributes[0]),
        }

    @fh_check
    def lookup(self, dir_handle, file_folder, auth=None):
        response = self.with_filehandle(
            dir_handle,
            self.getattr_op(DEFAULT_ATTRIBUTES),
            self.lookup_op(str_to_bytes(file_folder)),
            self.getfh_op(),
            self.getattr_op(DEFAULT_ATTRIBUTES),
            tag=b"lookup",
            auth=auth,
            check=False,
        )
        attributes = operation_results(response, const.OP_GETATTR)
        status = operation_status(response, const.OP_GETFH)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes(attributes[0] if attributes else None))
        filehandle = self.operation_result(response, const.OP_GETFH)
        self.locations[filehandle] = (dir_handle, str_to_bytes(file_folder))
        return {
            "status": status,
            "resok": {
                "object": {"data": filehandle},
                "obj_attributes": post_op_attributes(attributes[1] if len(attributes) > 1 else None),
                "dir_attributes": post_op_attributes(attributes[0]),
            },
        }

    @fh_check
    def access(self, file_handle, access_option, auth=None):
        response = self.with_filehandle(file_handle, self.getattr_op(DEFAULT_ATTRIBUTES), self.access_op(access_option), tag=b"access", auth=auth, check=False)
        attributes = operation_results(response, const.OP_GETATTR)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes(attributes[0] if attributes else None))
        return {
            "status": response.status,
            "resok": {
                "obj_attributes": post_op_attributes(attributes[0]),
                "access": self.operation_result(response, const.OP_ACCESS).access,
            },
        }

    @fh_check
    def readlink(self, file_handle, auth=None):
        response = self.with_filehandle(file_handle, self.getattr_op(DEFAULT_ATTRIBUTES), self.readlink_op(), tag=b"readlink", auth=auth, check=False)
        attributes = operation_results(response, const.OP_GETATTR)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes(attributes[0] if attributes else None))
        return {
            "status": response.status,
            "resok": {
                "symlink_attributes": post_op_attributes(attributes[0]),
                "data": self.operation_result(response, const.OP_READLINK),
            },
        }

    @fh_check
    def read(self, file_handle, offset=0, chunk_count=1024 * 1024, auth=None):
        try:
            opened_file = self.ensure_open(file_handle, const.OPEN4_SHARE_ACCESS_READ, auth)
        except NFS4Error as e:
            return response_failure(e.status, post_op_attributes())
        response = self.with_filehandle(
            opened_file.filehandle,
            self.getattr_op(DEFAULT_ATTRIBUTES),
            self.read_op(opened_file.stateid, offset, chunk_count),
            tag=b"read",
            auth=auth,
            check=False,
        )
        attributes = operation_results(response, const.OP_GETATTR)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes(attributes[0] if attributes else None))
        read_result = self.operation_result(response, const.OP_READ)
        return {
            "status": response.status,
            "resok": {
                "file_attributes": post_op_attributes(attributes[0]),
                "count": len(read_result.data),
                "eof": read_result.eof,
                "data": read_result.data,
            },
        }

    @fh_check
    def write(self, file_handle, offset, count, content, stable_how, auth=None):
        if count != len(str_to_bytes(content)):
            return response_failure(const.NFS4ERR_INVAL, wcc_data())
        try:
            opened_file = self.ensure_open(file_handle, const.OPEN4_SHARE_ACCESS_WRITE, auth)
        except NFS4Error as e:
            return response_failure(e.status, wcc_data())
        response = self.with_filehandle(
            opened_file.filehandle,
            self.getattr_op(DEFAULT_ATTRIBUTES),
            self.write_op(opened_file.stateid, offset, str_to_bytes(content), stable_how),
            self.getattr_op(DEFAULT_ATTRIBUTES),
            tag=b"write",
            auth=auth,
            check=False,
        )
        attributes = operation_results(response, const.OP_GETATTR)
        status = operation_status(response, const.OP_WRITE)
        if status != const.NFS4_OK:
            return response_failure(status, wcc_data(before=attributes[0] if attributes else None))
        write_result = self.operation_result(response, const.OP_WRITE)
        return {
            "status": status,
            "resok": {
                "file_wcc": wcc_data(attributes[1] if len(attributes) > 1 else None, attributes[0]),
                "count": write_result.count,
                "committed": write_result.committed,
                "verf": write_result.writeverf,
            },
        }

    @fh_check
    def create(
        self,
        dir_handle,
        file_name,
        create_mode,
        mode=None,
        uid=None,
        gid=None,
        size=None,
        atime_flag=v3.SET_TO_SERVER_TIME,
        atime_s=None,
        atime_us=None,
        mtime_flag=v3.SET_TO_SERVER_TIME,
        mtime_s=None,
        mtime_us=None,
        verf="0",
        auth=None,
    ):
        if create_mode not in (v3.UNCHECKED, v3.GUARDED, v3.EXCLUSIVE):
            raise ValueError("create_mode must be UNCHECKED, GUARDED, or EXCLUSIVE")
        parent_status, parent_before = self.get_attributes4(dir_handle, auth=auth)
        create_attributes = nfs4_attributes(mode, uid, gid, size, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us)
        try:
            self.ensure_client(auth)
            opened_file = self.open_file(
                dir_handle,
                str_to_bytes(file_name),
                const.OPEN4_SHARE_ACCESS_BOTH,
                openhow=types.OpenFlag4(
                    const.OPEN4_CREATE,
                    types.CreateHow4(
                        create_mode,
                        createattrs=create_attributes if create_mode != v3.EXCLUSIVE else None,
                        createverf=verifier8(verf) if create_mode == v3.EXCLUSIVE else None,
                    ),
                ),
                auth=auth,
            )
        except NFS4Error as e:
            return response_failure(e.status, wcc_data(before=parent_before if parent_status == const.NFS4_OK else None))
        self.locations[opened_file.filehandle] = (dir_handle, str_to_bytes(file_name))
        self.opened[opened_file.filehandle] = opened_file
        if create_mode == v3.EXCLUSIVE:
            response = self.with_filehandle(
                opened_file.filehandle, self.setattr_op(opened_file.stateid, create_attributes), tag=b"exclusive-create-setattr", auth=auth, check=False
            )
            if response.status != const.NFS4_OK:
                try:
                    self.close_handle(opened_file.filehandle, auth)
                except NFS4Error as e:
                    logger.debug("Unable to close %r after exclusive CREATE SETATTR failed: %s", opened_file.filehandle, e)
                self.locations.pop(opened_file.filehandle, None)
                return response_failure(response.status, wcc_data(before=parent_before if parent_status == const.NFS4_OK else None))
        object_status, object_attributes = self.get_attributes4(opened_file.filehandle, auth=auth)
        parent_status, parent_after = self.get_attributes4(dir_handle, auth=auth)
        return {
            "status": const.NFS4_OK,
            "resok": {
                "obj": post_op_handle(opened_file.filehandle),
                "obj_attributes": post_op_attributes(object_attributes if object_status == const.NFS4_OK else None),
                "dir_wcc": wcc_data(parent_after if parent_status == const.NFS4_OK else None, parent_before),
            },
        }

    def create_object(self, dir_handle, name, objtype, attributes, auth=None):
        response = self.with_filehandle(
            dir_handle,
            self.getattr_op(DEFAULT_ATTRIBUTES),
            self.savefh_op(),
            self.create_op(objtype, str_to_bytes(name), attributes),
            self.getfh_op(),
            self.getattr_op(DEFAULT_ATTRIBUTES),
            self.restorefh_op(),
            self.getattr_op(DEFAULT_ATTRIBUTES),
            tag=b"create",
            auth=auth,
            check=False,
        )
        found_attributes = operation_results(response, const.OP_GETATTR)
        status = operation_status(response, const.OP_CREATE)
        if status != const.NFS4_OK:
            return response_failure(status, wcc_data(before=found_attributes[0] if found_attributes else None))
        if operation_results(response, const.OP_GETFH):
            self.locations[operation_results(response, const.OP_GETFH)[0]] = (dir_handle, str_to_bytes(name))
        return {
            "status": status,
            "resok": {
                "obj": post_op_handle(operation_results(response, const.OP_GETFH)[0] if operation_results(response, const.OP_GETFH) else None),
                "obj_attributes": post_op_attributes(found_attributes[1] if len(found_attributes) > 1 else None),
                "dir_wcc": wcc_data(found_attributes[2] if len(found_attributes) > 2 else None, found_attributes[0]),
            },
        }

    @fh_check
    def mkdir(
        self,
        dir_handle,
        dir_name,
        mode=None,
        uid=None,
        gid=None,
        atime_flag=v3.SET_TO_SERVER_TIME,
        atime_s=None,
        atime_us=None,
        mtime_flag=v3.SET_TO_SERVER_TIME,
        mtime_s=None,
        mtime_us=None,
        auth=None,
    ):
        return self.create_object(
            dir_handle,
            dir_name,
            types.CreateType4(const.NF4DIR),
            nfs4_attributes(mode, uid, gid, None, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us),
            auth,
        )

    @fh_check
    def symlink(self, dir_handle, link_name, link_to_path, auth=None):
        return self.create_object(dir_handle, link_name, types.CreateType4(const.NF4LNK, linkdata=str_to_bytes(link_to_path)), types.Fattr4(), auth)

    @fh_check
    def mknod(
        self,
        dir_handle,
        file_name,
        ftype,
        mode=None,
        uid=None,
        gid=None,
        atime_flag=v3.SET_TO_SERVER_TIME,
        atime_s=None,
        atime_us=None,
        mtime_flag=v3.SET_TO_SERVER_TIME,
        mtime_s=None,
        mtime_us=None,
        spec_major=0,
        spec_minor=0,
        auth=None,
    ):
        if ftype not in (v3.NF3CHR, v3.NF3BLK, v3.NF3SOCK, v3.NF3FIFO):
            raise ValueError("ftype must be NF3CHR, NF3BLK, NF3SOCK, or NF3FIFO")
        return self.create_object(
            dir_handle,
            file_name,
            types.CreateType4(ftype, devdata=types.SpecData4(spec_major, spec_minor) if ftype in (v3.NF3CHR, v3.NF3BLK) else None),
            nfs4_attributes(mode, uid, gid, None, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us),
            auth,
        )

    def remove_name(self, dir_handle, name, auth=None):
        for file_handle, location in tuple(self.locations.items()):
            if location == (dir_handle, str_to_bytes(name)):
                try:
                    self.close_handle(file_handle, auth)
                except NFS4Error as e:
                    logger.debug("Unable to close %r before REMOVE: %s", file_handle, e)
        response = self.with_filehandle(
            dir_handle,
            self.getattr_op(DEFAULT_ATTRIBUTES),
            self.remove_op(str_to_bytes(name)),
            self.getattr_op(DEFAULT_ATTRIBUTES),
            tag=b"remove",
            auth=auth,
            check=False,
        )
        attributes = operation_results(response, const.OP_GETATTR)
        status = operation_status(response, const.OP_REMOVE)
        if status != const.NFS4_OK:
            return wcc_failure(status, wcc_data(before=attributes[0] if attributes else None))
        for file_handle, location in tuple(self.locations.items()):
            if location == (dir_handle, str_to_bytes(name)):
                self.locations.pop(file_handle, None)
                self.opened.pop(file_handle, None)
        return {
            "status": status,
            "resok": wcc_data(attributes[1] if len(attributes) > 1 else None, attributes[0]),
        }

    @fh_check
    def remove(self, dir_handle, file_name, auth=None):
        return self.remove_name(dir_handle, file_name, auth)

    @fh_check
    def rmdir(self, dir_handle, dir_name, auth=None):
        return self.remove_name(dir_handle, dir_name, auth)

    @fh_check
    def rename(self, dir_handle_from, from_name, dir_handle_to, to_name, auth=None):
        if not isinstance(dir_handle_to, bytes):
            raise TypeError("file handle should be bytes")
        response = self.compound(
            (
                self.putfh_op(dir_handle_from),
                self.getattr_op(DEFAULT_ATTRIBUTES),
                self.savefh_op(),
                self.putfh_op(dir_handle_to),
                self.getattr_op(DEFAULT_ATTRIBUTES),
                self.rename_op(str_to_bytes(from_name), str_to_bytes(to_name)),
                self.getattr_op(DEFAULT_ATTRIBUTES),
                self.restorefh_op(),
                self.getattr_op(DEFAULT_ATTRIBUTES),
            ),
            tag=b"rename",
            auth=auth,
            check=False,
        )
        attributes = operation_results(response, const.OP_GETATTR)
        status = operation_status(response, const.OP_RENAME)
        if status == const.NFS4_OK:
            for file_handle, location in tuple(self.locations.items()):
                if location == (dir_handle_from, str_to_bytes(from_name)):
                    self.locations[file_handle] = (dir_handle_to, str_to_bytes(to_name))
        return {
            "status": status,
            "res": {
                "fromdir_wcc": wcc_data(attributes[3] if len(attributes) > 3 else None, attributes[0] if attributes else None),
                "todir_wcc": wcc_data(attributes[2] if len(attributes) > 2 else None, attributes[1] if len(attributes) > 1 else None),
            },
        }

    @fh_check
    def link(self, file_handle, link_to_dir_handle, link_name, auth=None):
        if not isinstance(link_to_dir_handle, bytes):
            raise TypeError("file handle should be bytes")
        response = self.compound(
            (
                self.putfh_op(file_handle),
                self.savefh_op(),
                self.putfh_op(link_to_dir_handle),
                self.getattr_op(DEFAULT_ATTRIBUTES),
                self.link_op(str_to_bytes(link_name)),
                self.getattr_op(DEFAULT_ATTRIBUTES),
                self.restorefh_op(),
                self.getattr_op(DEFAULT_ATTRIBUTES),
            ),
            tag=b"link",
            auth=auth,
            check=False,
        )
        attributes = operation_results(response, const.OP_GETATTR)
        status = operation_status(response, const.OP_LINK)
        if status == const.NFS4_OK:
            self.locations[file_handle] = (link_to_dir_handle, str_to_bytes(link_name))
        return {
            "status": status,
            "res": {
                "file_attributes": post_op_attributes(attributes[2] if len(attributes) > 2 else None),
                "linkdir_wcc": wcc_data(attributes[1] if len(attributes) > 1 else None, attributes[0] if attributes else None),
            },
        }

    def read_directory(self, dir_handle, cookie, cookie_verf, dircount, maxcount, include_attributes, auth):
        response = self.with_filehandle(
            dir_handle,
            self.getattr_op(DEFAULT_ATTRIBUTES),
            self.readdir_op(
                cookie,
                b"\0" * const.NFS4_VERIFIER_SIZE if cookie == 0 else verifier8(cookie_verf),
                dircount,
                maxcount,
                DIRECTORY_ATTRIBUTES if include_attributes else READDIR_ATTRIBUTES,
            ),
            tag=b"readdirplus" if include_attributes else b"readdir",
            auth=auth,
            check=False,
        )
        attributes = operation_results(response, const.OP_GETATTR)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes(attributes[0] if attributes else None))
        page = self.operation_result(response, const.OP_READDIR)
        if include_attributes:
            for entry in page.entries:
                if const.FATTR4_FILEHANDLE in entry.attrs.attributes:
                    self.locations[entry.attrs.attributes[const.FATTR4_FILEHANDLE]] = (dir_handle, str_to_bytes(entry.name))
        return {
            "status": response.status,
            "resok": {
                "dir_attributes": post_op_attributes(attributes[0]),
                "cookieverf": page.cookieverf,
                "reply": {
                    "entries": linked_entries(page.entries, include_attributes),
                    "eof": page.eof,
                },
            },
        }

    @fh_check
    def readdir(self, dir_handle, cookie=0, cookie_verf=b"0", count=4096, auth=None):
        return self.read_directory(dir_handle, cookie, cookie_verf, count, count, False, auth)

    @fh_check
    def readdirplus(self, dir_handle, cookie=0, cookie_verf=b"0", dircount=4096, maxcount=32768, auth=None):
        return self.read_directory(dir_handle, cookie, cookie_verf, dircount, maxcount, True, auth)

    @fh_check
    def fsstat(self, file_handle, auth=None):
        status, attributes = self.get_attributes4(file_handle, FILESYSTEM_ATTRIBUTES, auth)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes())
        values = attributes.attributes
        return {
            "status": status,
            "resok": {
                "obj_attributes": post_op_attributes(attributes),
                "tbytes": values.get(const.FATTR4_SPACE_TOTAL, 0),
                "fbytes": values.get(const.FATTR4_SPACE_FREE, 0),
                "abytes": values.get(const.FATTR4_SPACE_AVAIL, 0),
                "tfiles": values.get(const.FATTR4_FILES_TOTAL, 0),
                "ffiles": values.get(const.FATTR4_FILES_FREE, 0),
                "afiles": values.get(const.FATTR4_FILES_AVAIL, 0),
                "invarsec": 0,
            },
        }

    @fh_check
    def fsinfo(self, file_handle, auth=None):
        status, attributes = self.get_attributes4(file_handle, FSINFO_ATTRIBUTES, auth)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes())
        values = attributes.attributes
        properties = 0
        if values.get(const.FATTR4_LINK_SUPPORT):
            properties |= v3.FSF3_LINK
        if values.get(const.FATTR4_SYMLINK_SUPPORT):
            properties |= v3.FSF3_SYMLINK
        if values.get(const.FATTR4_HOMOGENEOUS):
            properties |= v3.FSF3_HOMOGENEOUS
        if values.get(const.FATTR4_CANSETTIME):
            properties |= v3.FSF3_CANSETTIME
        return {
            "status": status,
            "resok": {
                "obj_attributes": post_op_attributes(attributes),
                "rtmax": values.get(const.FATTR4_MAXREAD, 1024 * 1024),
                "rtpref": values.get(const.FATTR4_MAXREAD, 1024 * 1024),
                "rtmult": 1,
                "wtmax": values.get(const.FATTR4_MAXWRITE, 1024 * 1024),
                "wtpref": values.get(const.FATTR4_MAXWRITE, 1024 * 1024),
                "wtmult": 1,
                "dtpref": values.get(const.FATTR4_MAXREAD, 32 * 1024),
                "maxfilesize": values.get(const.FATTR4_MAXFILESIZE, 0),
                "time_delta": nfs3_time(values.get(const.FATTR4_TIME_DELTA)),
                "properties": properties,
            },
        }

    @fh_check
    def pathconf(self, file_handle, auth=None):
        status, attributes = self.get_attributes4(file_handle, PATHCONF_ATTRIBUTES, auth)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes())
        values = attributes.attributes
        return {
            "status": status,
            "resok": {
                "obj_attributes": post_op_attributes(attributes),
                "linkmax": values.get(const.FATTR4_MAXLINK, 0),
                "name_max": values.get(const.FATTR4_MAXNAME, 0),
                "no_trunc": values.get(const.FATTR4_NO_TRUNC, False),
                "chown_restricted": values.get(const.FATTR4_CHOWN_RESTRICTED, False),
                "case_insensitive": values.get(const.FATTR4_CASE_INSENSITIVE, False),
                "case_preserving": values.get(const.FATTR4_CASE_PRESERVING, True),
            },
        }

    @fh_check
    def commit(self, file_handle, count=0, offset=0, auth=None):
        response = self.with_filehandle(
            file_handle,
            self.getattr_op(DEFAULT_ATTRIBUTES),
            self.commit_op(offset, count),
            self.getattr_op(DEFAULT_ATTRIBUTES),
            tag=b"commit",
            auth=auth,
            check=False,
        )
        attributes = operation_results(response, const.OP_GETATTR)
        status = operation_status(response, const.OP_COMMIT)
        if status != const.NFS4_OK:
            return response_failure(status, wcc_data(before=attributes[0] if attributes else None))
        return {
            "status": status,
            "resok": {
                "file_wcc": wcc_data(attributes[1] if len(attributes) > 1 else None, attributes[0]),
                "verf": self.operation_result(response, const.OP_COMMIT).writeverf,
            },
        }

    def validate_filehandle(self, filehandle, directory=False, auth=None):
        response = self.getattr(filehandle, auth)
        if response["status"] != const.NFS4_OK:
            return False
        if directory and response["attributes"]["type"] != const.NF4DIR:
            return False
        return not directory or self.readdirplus(filehandle, auth=auth)["status"] == const.NFS4_OK
