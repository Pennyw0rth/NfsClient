from abc import ABC, abstractmethod
from dataclasses import dataclass

from . import nfs4_const as const
from . import nfs4_types as types
from .nfs42_const import NFS_OPNUM4 as ALL_NFS_OPNUM4, NFSSTAT4 as ALL_NFSSTAT4
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
EXPLICIT_AUTH_NONE = object()


@dataclass(frozen=True, slots=True)
class ClientIdentity:
    owner_id: bytes
    verifier: bytes

    def __post_init__(self):
        if not isinstance(self.owner_id, bytes) or not self.owner_id:
            raise ValueError("client owner ID must be non-empty bytes")
        if not isinstance(self.verifier, bytes) or len(self.verifier) != const.NFS4_VERIFIER_SIZE:
            raise ValueError(f"client verifier must be {const.NFS4_VERIFIER_SIZE} bytes")


class NFS4Error(Exception):
    def __init__(self, status, operation=None, index=None, response=None):
        self.status = status
        self.operation = operation
        self.index = index
        self.response = response
        super().__init__(self.message())

    def message(self):
        if self.operation is None:
            return ALL_NFSSTAT4.get(self.status, f"NFSv4 status {self.status}")
        return f"{ALL_NFS_OPNUM4.get(self.operation, f'operation {self.operation}')} failed with {ALL_NFSSTAT4.get(self.status, self.status)}"


class NFS4UncertainError(Exception):
    def __init__(self, request):
        self.request = request
        super().__init__("the NFSv4 request outcome is unknown; replay the retained request before reusing its state")


class NFSv4Protocol(RPC, ABC):
    minor_version = 0
    legal_operations = const.NFS4_OPERATIONS
    packer_class = NFS4Packer
    unpacker_class = NFS4Unpacker

    def __init__(self, host, port=2049, timeout=5, auth=None, client_identity=None):
        super().__init__(host, port, timeout)
        self.auth = auth
        self.client_identity = client_identity

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.disconnect()

    def effective_auth(self, auth):
        if auth is EXPLICIT_AUTH_NONE:
            return None
        return self.auth if auth is None else auth

    @staticmethod
    def saved_auth(auth):
        return EXPLICIT_AUTH_NONE if auth is None else auth

    @staticmethod
    def auth_identity(auth):
        if isinstance(auth, dict):
            return (auth.get("flavor"), str_to_bytes(auth.get("machine_name", b"")), auth.get("uid"), auth.get("gid"), tuple(auth.get("aux_gid", ())))
        if hasattr(auth, "principal_identity"):
            return auth.principal_identity
        return id(auth)

    @staticmethod
    def auth_snapshot(auth):
        if not isinstance(auth, dict):
            return auth
        auth = dict(auth)
        auth["aux_gid"] = tuple(auth.get("aux_gid", ()))
        return auth

    def nfs_request(self, procedure, args, auth):
        return super().request(const.NFS_PROGRAM, const.NFS_V4, procedure, data=args, auth=self.effective_auth(auth))

    def null(self, auth=None):
        self.nfs_request(const.NFS4_PROCEDURE_NULL, b"", auth)

    def validate_operations(self, operations):
        for operation in operations:
            if operation.op not in self.legal_operations:
                raise ValueError(f"{const.NFS_OPNUM4.get(operation.op, operation.op)} is not legal in NFSv4.{self.minor_version}")

    @abstractmethod
    def compound(self, operations, tag=b"", auth=None, check=True):
        operations = tuple(operations)
        self.validate_operations(operations)
        packer = self.packer_class()
        packer.pack_compound_args(types.Compound4Args(tag, self.minor_version, operations))
        unpacker = self.unpacker_class(self.nfs_request(const.NFS4_PROCEDURE_COMPOUND, packer.get_buffer(), auth))
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
    def getattr_op(attr_request=types.Bitmap4()):
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
    def readdir_op(cookie=0, cookieverf=b"\0" * const.NFS4_VERIFIER_SIZE, dircount=32 * 1024, maxcount=64 * 1024, attr_request=types.Bitmap4()):
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


__all__ = ("ClientIdentity", "DEFAULT_ATTRIBUTES", "DIRECTORY_ATTRIBUTES", "NFS4Error", "NFS4UncertainError", "NFSv4Protocol")
