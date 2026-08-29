import struct
import unittest

from pyNfsClient import nfs4_const as const
from pyNfsClient.nfs4_pack import NFS4CodecError, NFS4Packer, NFS4Unpacker
from pyNfsClient.nfs4_types import (
    Access4Args, Access4Res, ArgOp4, Bitmap4, CallbackClient4,
    ChangeInfo4, ClientAddr4, Close4Args, Commit4Args, Commit4Res,
    Compound4Args, Compound4Res, Create4Args, Create4Res, CreateHow4,
    CreateType4, DelegPurge4Args, DelegReturn4Args, Entry4, ExistingLockOwner4,
    Fattr4, FsLocation4, FsLocations4, Fsid4, GetAttr4Args,
    Link4Args, Link4Res, Lock4Args, LockDenied4, Locker4,
    LockOwner4, LockT4Args, LockU4Args, Lookup4Args, NfsAce4,
    NfsClientId4, NfsModifiedLimit4, NfsSpaceLimit4, NfsTime4, NVerify4Args,
    Open4Args, Open4Res, OpenAttr4Args, OpenClaim4, OpenClaimDelegateCur4,
    OpenConfirm4Args, OpenDelegation4, OpenDowngrade4Args, OpenFlag4, OpenOwner4,
    OpenReadDelegation4, OpenToLockOwner4, OpenWriteDelegation4, PutFh4Args, Read4Args,
    Read4Res, ReadDir4Args, ReadDir4Res, ReleaseLockOwner4Args, Remove4Args,
    Rename4Args, Rename4Res, Renew4Args, ResOp4, RpcSecGssInfo4,
    SecInfo4, SecInfo4Args, SetAttr4Args, SetAttr4Res, SetClientId4Args,
    SetClientId4Res, SetClientIdConfirm4Args, SetTime4, SpecData4, Stateid4,
    Verify4Args, Write4Args, Write4Res,
)


STATEID = Stateid4(7, bytes(range(12)))
VERIFIER = b"12345678"
CHANGE = ChangeInfo4(True, 10, 11)


def roundtrip_args(value):
    packer = NFS4Packer()
    packer.pack_compound_args(value)
    unpacker = NFS4Unpacker(packer.get_buffer())
    result = unpacker.unpack_compound_args()
    unpacker.done()
    return result


def roundtrip_res(value):
    packer = NFS4Packer()
    packer.pack_compound_res(value)
    unpacker = NFS4Unpacker(packer.get_buffer())
    result = unpacker.unpack_compound_res()
    unpacker.done()
    return result


class NFS4CodecTests(unittest.TestCase):
    def test_bitmap_bit_order(self):
        self.assertEqual(Bitmap4.from_bits(0, 1, 31, 32, 55).words, (0x80000003, 0x00800001))
        self.assertEqual(Bitmap4((0x80000003, 0x00800001)).bits(), (0, 1, 31, 32, 55))

    def test_putrootfh_getfh_golden_request(self):
        packer = NFS4Packer()
        packer.pack_compound_args(Compound4Args(argarray=(ArgOp4(const.OP_PUTROOTFH), ArgOp4(const.OP_GETFH))))
        self.assertEqual(packer.get_buffer(), bytes.fromhex("00000000 00000000 00000002 00000018 0000000a"))

    def test_all_attributes_roundtrip(self):
        attributes = {
            const.FATTR4_SUPPORTED_ATTRS: Bitmap4.from_bits(*range(56)),
            const.FATTR4_TYPE: const.NF4REG,
            const.FATTR4_FH_EXPIRE_TYPE: const.FH4_PERSISTENT,
            const.FATTR4_CHANGE: 0x0102030405060708,
            const.FATTR4_SIZE: 4096,
            const.FATTR4_LINK_SUPPORT: True,
            const.FATTR4_SYMLINK_SUPPORT: True,
            const.FATTR4_NAMED_ATTR: False,
            const.FATTR4_FSID: Fsid4(1, 2),
            const.FATTR4_UNIQUE_HANDLES: True,
            const.FATTR4_LEASE_TIME: 90,
            const.FATTR4_RDATTR_ERROR: const.NFS4_OK,
            const.FATTR4_ACL: (
                NfsAce4(const.ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, const.ACE4_GENERIC_READ, b"OWNER@"),
            ),
            const.FATTR4_ACLSUPPORT: const.ACL4_SUPPORT_ALLOW_ACL,
            const.FATTR4_ARCHIVE: False,
            const.FATTR4_CANSETTIME: True,
            const.FATTR4_CASE_INSENSITIVE: False,
            const.FATTR4_CASE_PRESERVING: True,
            const.FATTR4_CHOWN_RESTRICTED: True,
            const.FATTR4_FILEHANDLE: b"filehandle",
            const.FATTR4_FILEID: 12,
            const.FATTR4_FILES_AVAIL: 13,
            const.FATTR4_FILES_FREE: 14,
            const.FATTR4_FILES_TOTAL: 15,
            const.FATTR4_FS_LOCATIONS: FsLocations4(
                (b"export",),
                (
                    FsLocation4((b"nfs.example", b"192.0.2.1"), (b"replica",)),
                ),
            ),
            const.FATTR4_HIDDEN: False,
            const.FATTR4_HOMOGENEOUS: True,
            const.FATTR4_MAXFILESIZE: (1 << 63) - 1,
            const.FATTR4_MAXLINK: 32000,
            const.FATTR4_MAXNAME: 255,
            const.FATTR4_MAXREAD: 1048576,
            const.FATTR4_MAXWRITE: 1048576,
            const.FATTR4_MIMETYPE: b"application/octet-stream",
            const.FATTR4_MODE: 0o640,
            const.FATTR4_NO_TRUNC: True,
            const.FATTR4_NUMLINKS: 2,
            const.FATTR4_OWNER: b"1000",
            const.FATTR4_OWNER_GROUP: b"1000",
            const.FATTR4_QUOTA_AVAIL_HARD: 100,
            const.FATTR4_QUOTA_AVAIL_SOFT: 101,
            const.FATTR4_QUOTA_USED: 102,
            const.FATTR4_RAWDEV: SpecData4(8, 1),
            const.FATTR4_SPACE_AVAIL: 103,
            const.FATTR4_SPACE_FREE: 104,
            const.FATTR4_SPACE_TOTAL: 105,
            const.FATTR4_SPACE_USED: 106,
            const.FATTR4_SYSTEM: False,
            const.FATTR4_TIME_ACCESS: NfsTime4(-1, 1),
            const.FATTR4_TIME_ACCESS_SET: SetTime4(const.SET_TO_CLIENT_TIME4, NfsTime4(2, 3)),
            const.FATTR4_TIME_BACKUP: NfsTime4(4, 5),
            const.FATTR4_TIME_CREATE: NfsTime4(6, 7),
            const.FATTR4_TIME_DELTA: NfsTime4(0, 1),
            const.FATTR4_TIME_METADATA: NfsTime4(8, 9),
            const.FATTR4_TIME_MODIFY: NfsTime4(10, 11),
            const.FATTR4_TIME_MODIFY_SET: SetTime4(const.SET_TO_SERVER_TIME4),
            const.FATTR4_MOUNTED_ON_FILEID: 107,
        }
        self.assertEqual(
            roundtrip_args(Compound4Args(argarray=(ArgOp4(const.OP_VERIFY, Verify4Args(Fattr4(attributes))),))).argarray[0].arg.obj_attributes,
            Fattr4(attributes),
        )

    def test_all_forechannel_argument_operations_roundtrip(self):
        owner = LockOwner4(99, b"lock-owner")
        operations = (
            ArgOp4(const.OP_ACCESS, Access4Args(const.ACCESS4_READ | const.ACCESS4_LOOKUP)),
            ArgOp4(const.OP_CLOSE, Close4Args(1, STATEID)),
            ArgOp4(const.OP_COMMIT, Commit4Args(2, 3)),
            ArgOp4(const.OP_CREATE, Create4Args(CreateType4(const.NF4DIR), b"new", Fattr4({const.FATTR4_MODE: 0o755}))),
            ArgOp4(const.OP_DELEGPURGE, DelegPurge4Args(4)),
            ArgOp4(const.OP_DELEGRETURN, DelegReturn4Args(STATEID)),
            ArgOp4(const.OP_GETATTR, GetAttr4Args(Bitmap4.from_bits(const.FATTR4_TYPE))),
            ArgOp4(const.OP_GETFH),
            ArgOp4(const.OP_LINK, Link4Args(b"hardlink")),
            ArgOp4(const.OP_LOCK, Lock4Args(const.WRITE_LT, False, 5, 6, Locker4(True, OpenToLockOwner4(2, STATEID, 3, owner)))),
            ArgOp4(const.OP_LOCKT, LockT4Args(const.READ_LT, 7, 8, owner)),
            ArgOp4(const.OP_LOCKU, LockU4Args(const.WRITE_LT, 4, STATEID, 9, 10)),
            ArgOp4(const.OP_LOOKUP, Lookup4Args(b"path")),
            ArgOp4(const.OP_LOOKUPP),
            ArgOp4(const.OP_NVERIFY, NVerify4Args(Fattr4({const.FATTR4_SIZE: 11}))),
            ArgOp4(
                const.OP_OPEN,
                Open4Args(
                    5,
                    const.OPEN4_SHARE_ACCESS_READ,
                    const.OPEN4_SHARE_DENY_NONE,
                    OpenOwner4(99, b"open-owner"),
                    OpenFlag4(),
                    OpenClaim4(const.CLAIM_NULL, file=b"file"),
                ),
            ),
            ArgOp4(const.OP_OPENATTR, OpenAttr4Args(False)),
            ArgOp4(const.OP_OPEN_CONFIRM, OpenConfirm4Args(STATEID, 6)),
            ArgOp4(const.OP_OPEN_DOWNGRADE, OpenDowngrade4Args(STATEID, 7, const.OPEN4_SHARE_ACCESS_READ, const.OPEN4_SHARE_DENY_NONE)),
            ArgOp4(const.OP_PUTFH, PutFh4Args(b"fh")),
            ArgOp4(const.OP_PUTPUBFH),
            ArgOp4(const.OP_PUTROOTFH),
            ArgOp4(const.OP_READ, Read4Args(STATEID, 12, 13)),
            ArgOp4(const.OP_READDIR, ReadDir4Args(14, VERIFIER, 4096, 8192, Bitmap4.from_bits(const.FATTR4_TYPE))),
            ArgOp4(const.OP_READLINK),
            ArgOp4(const.OP_REMOVE, Remove4Args(b"old")),
            ArgOp4(const.OP_RENAME, Rename4Args(b"old", b"new")),
            ArgOp4(const.OP_RENEW, Renew4Args(99)),
            ArgOp4(const.OP_RESTOREFH),
            ArgOp4(const.OP_SAVEFH),
            ArgOp4(const.OP_SECINFO, SecInfo4Args(b"secure")),
            ArgOp4(const.OP_SETATTR, SetAttr4Args(STATEID, Fattr4({const.FATTR4_MODE: 0o600}))),
            ArgOp4(const.OP_SETCLIENTID, SetClientId4Args(NfsClientId4(VERIFIER, b"client-id"), CallbackClient4(0, ClientAddr4(b"tcp", b"0.0.0.0.0.0")), 0)),
            ArgOp4(const.OP_SETCLIENTID_CONFIRM, SetClientIdConfirm4Args(99, VERIFIER)),
            ArgOp4(const.OP_VERIFY, Verify4Args(Fattr4({const.FATTR4_TYPE: const.NF4REG}))),
            ArgOp4(const.OP_WRITE, Write4Args(STATEID, 15, const.FILE_SYNC4, b"data")),
            ArgOp4(const.OP_RELEASE_LOCKOWNER, ReleaseLockOwner4Args(owner)),
        )
        self.assertEqual(roundtrip_args(Compound4Args(b"all", 0, operations)), Compound4Args(b"all", 0, operations))
        self.assertEqual({operation.op for operation in operations}, const.NFS4_OPERATIONS)

    def test_existing_lock_owner_roundtrip(self):
        operation = ArgOp4(const.OP_LOCK, Lock4Args(const.READ_LT, True, 0, 1, Locker4(False, lock_owner=ExistingLockOwner4(STATEID, 3))))
        self.assertEqual(roundtrip_args(Compound4Args(argarray=(operation,))).argarray[0], operation)

    def test_create_and_open_union_arms_roundtrip(self):
        create_operations = (
            ArgOp4(const.OP_CREATE, Create4Args(CreateType4(const.NF4LNK, linkdata=b"target"), b"link")),
            ArgOp4(const.OP_CREATE, Create4Args(CreateType4(const.NF4BLK, devdata=SpecData4(8, 0)), b"block")),
            ArgOp4(const.OP_CREATE, Create4Args(CreateType4(const.NF4CHR, devdata=SpecData4(1, 3)), b"char")),
            ArgOp4(const.OP_CREATE, Create4Args(CreateType4(const.NF4SOCK), b"socket")),
            ArgOp4(const.OP_CREATE, Create4Args(CreateType4(const.NF4FIFO), b"fifo")),
        )
        open_operations = (
            ArgOp4(
                const.OP_OPEN,
                Open4Args(
                    1,
                    1,
                    0,
                    OpenOwner4(1, b"owner"),
                    OpenFlag4(const.OPEN4_CREATE, CreateHow4(const.UNCHECKED4, createattrs=Fattr4())),
                    OpenClaim4(const.CLAIM_NULL, file=b"new"),
                ),
            ),
            ArgOp4(
                const.OP_OPEN,
                Open4Args(
                    2,
                    1,
                    0,
                    OpenOwner4(1, b"owner"),
                    OpenFlag4(const.OPEN4_CREATE, CreateHow4(const.GUARDED4, createattrs=Fattr4({const.FATTR4_MODE: 0o600}))),
                    OpenClaim4(const.CLAIM_PREVIOUS, delegate_type=const.OPEN_DELEGATE_NONE),
                ),
            ),
            ArgOp4(
                const.OP_OPEN,
                Open4Args(
                    3,
                    1,
                    0,
                    OpenOwner4(1, b"owner"),
                    OpenFlag4(const.OPEN4_CREATE, CreateHow4(const.EXCLUSIVE4, createverf=VERIFIER)),
                    OpenClaim4(const.CLAIM_DELEGATE_CUR, delegate_cur_info=OpenClaimDelegateCur4(STATEID, b"delegated")),
                ),
            ),
            ArgOp4(
                const.OP_OPEN, Open4Args(4, 1, 0, OpenOwner4(1, b"owner"), OpenFlag4(), OpenClaim4(const.CLAIM_DELEGATE_PREV, file_delegate_prev=b"previous"))
            ),
        )
        value = Compound4Args(b"unions", 0, create_operations + open_operations)
        self.assertEqual(roundtrip_args(value), value)

    def test_success_results_roundtrip(self):
        results = (
            ResOp4(const.OP_ACCESS, const.NFS4_OK, Access4Res(0x3F, const.ACCESS4_READ)),
            ResOp4(const.OP_CLOSE, const.NFS4_OK, STATEID),
            ResOp4(const.OP_COMMIT, const.NFS4_OK, Commit4Res(VERIFIER)),
            ResOp4(const.OP_CREATE, const.NFS4_OK, Create4Res(CHANGE, Bitmap4.from_bits(const.FATTR4_MODE))),
            ResOp4(const.OP_DELEGPURGE, const.NFS4_OK),
            ResOp4(const.OP_DELEGRETURN, const.NFS4_OK),
            ResOp4(const.OP_GETATTR, const.NFS4_OK, Fattr4({const.FATTR4_TYPE: const.NF4DIR})),
            ResOp4(const.OP_GETFH, const.NFS4_OK, b"fh"),
            ResOp4(const.OP_LINK, const.NFS4_OK, Link4Res(CHANGE)),
            ResOp4(const.OP_LOCK, const.NFS4_OK, STATEID),
            ResOp4(const.OP_LOCKT, const.NFS4_OK),
            ResOp4(const.OP_LOCKU, const.NFS4_OK, STATEID),
            ResOp4(const.OP_LOOKUP, const.NFS4_OK),
            ResOp4(const.OP_LOOKUPP, const.NFS4_OK),
            ResOp4(const.OP_NVERIFY, const.NFS4_OK),
            ResOp4(const.OP_OPEN, const.NFS4_OK, Open4Res(STATEID, CHANGE, const.OPEN4_RESULT_CONFIRM, Bitmap4(), OpenDelegation4())),
            ResOp4(const.OP_OPENATTR, const.NFS4_OK),
            ResOp4(const.OP_OPEN_CONFIRM, const.NFS4_OK, STATEID),
            ResOp4(const.OP_OPEN_DOWNGRADE, const.NFS4_OK, STATEID),
            ResOp4(const.OP_PUTFH, const.NFS4_OK),
            ResOp4(const.OP_PUTPUBFH, const.NFS4_OK),
            ResOp4(const.OP_PUTROOTFH, const.NFS4_OK),
            ResOp4(const.OP_READ, const.NFS4_OK, Read4Res(True, b"contents")),
            ResOp4(
                const.OP_READDIR,
                const.NFS4_OK,
                ReadDir4Res(
                    VERIFIER,
                    (
                        Entry4(1, b"entry", Fattr4({const.FATTR4_TYPE: const.NF4REG})),
                    ),
                    True,
                ),
            ),
            ResOp4(const.OP_READLINK, const.NFS4_OK, b"target"),
            ResOp4(const.OP_REMOVE, const.NFS4_OK, CHANGE),
            ResOp4(const.OP_RENAME, const.NFS4_OK, Rename4Res(CHANGE, CHANGE)),
            ResOp4(const.OP_RENEW, const.NFS4_OK),
            ResOp4(const.OP_RESTOREFH, const.NFS4_OK),
            ResOp4(const.OP_SAVEFH, const.NFS4_OK),
            ResOp4(
                const.OP_SECINFO,
                const.NFS4_OK,
                (
                    SecInfo4(const.AUTH_SYS),
                    SecInfo4(const.RPCSEC_GSS, RpcSecGssInfo4(b"oid", 0, const.RPC_GSS_SVC_PRIVACY)),
                ),
            ),
            ResOp4(const.OP_SETATTR, const.NFS4_OK, SetAttr4Res(Bitmap4.from_bits(const.FATTR4_MODE))),
            ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, SetClientId4Res(99, VERIFIER)),
            ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK),
            ResOp4(const.OP_VERIFY, const.NFS4_OK),
            ResOp4(const.OP_WRITE, const.NFS4_OK, Write4Res(8, const.FILE_SYNC4, VERIFIER)),
            ResOp4(const.OP_RELEASE_LOCKOWNER, const.NFS4_OK),
        )
        value = Compound4Res(const.NFS4_OK, b"all", results)
        self.assertEqual(roundtrip_res(value), value)
        self.assertEqual({result.op for result in results}, const.NFS4_OPERATIONS)

    def test_result_union_error_arms_roundtrip(self):
        denied = LockDenied4(1, 2, const.WRITE_LT, LockOwner4(3, b"owner"))
        value = Compound4Res(
            const.NFS4ERR_DENIED,
            b"errors",
            (
                ResOp4(const.OP_LOCK, const.NFS4ERR_DENIED, denied),
                ResOp4(const.OP_LOCKT, const.NFS4ERR_DENIED, denied),
                ResOp4(const.OP_SETATTR, const.NFS4ERR_ATTRNOTSUPP, SetAttr4Res(Bitmap4())),
                ResOp4(const.OP_SETCLIENTID, const.NFS4ERR_CLID_INUSE, ClientAddr4(b"tcp", b"192.0.2.1.8.1")),
                ResOp4(const.OP_ILLEGAL, const.NFS4ERR_OP_ILLEGAL),
            ),
        )
        self.assertEqual(roundtrip_res(value), value)

    def test_read_delegation_roundtrip(self):
        result = Open4Res(
            STATEID,
            CHANGE,
            0,
            Bitmap4(),
            OpenDelegation4(const.OPEN_DELEGATE_READ, read=OpenReadDelegation4(STATEID, True, NfsAce4(0, 0, const.ACE4_GENERIC_READ, b"OWNER@"))),
        )
        value = Compound4Res(const.NFS4_OK, b"delegation", (ResOp4(const.OP_OPEN, const.NFS4_OK, result),))
        self.assertEqual(roundtrip_res(value), value)

    def test_write_delegation_limit_arms_roundtrip(self):
        for limit in (
            NfsSpaceLimit4(const.NFS_LIMIT_SIZE, filesize=4096),
            NfsSpaceLimit4(const.NFS_LIMIT_BLOCKS, mod_blocks=NfsModifiedLimit4(8, 512)),
        ):
            with self.subTest(limit=limit.limitby):
                result = Open4Res(
                    STATEID,
                    CHANGE,
                    0,
                    Bitmap4(),
                    OpenDelegation4(
                        const.OPEN_DELEGATE_WRITE, write=OpenWriteDelegation4(STATEID, False, limit, NfsAce4(0, 0, const.ACE4_GENERIC_WRITE, b"OWNER@"))
                    ),
                )
                value = Compound4Res(const.NFS4_OK, b"write-delegation", (ResOp4(const.OP_OPEN, const.NFS4_OK, result),))
                self.assertEqual(roundtrip_res(value), value)

    def test_rejects_minor_version_one(self):
        packer = NFS4Packer()
        with self.assertRaises(NFS4CodecError):
            packer.pack_compound_args(Compound4Args(minorversion=1))
        with self.assertRaises(NFS4CodecError):
            NFS4Unpacker(struct.pack(">LLL", 0, 1, 0)).unpack_compound_args()

    def test_rejects_invalid_operation_and_status(self):
        with self.assertRaises(NFS4CodecError):
            roundtrip_args(Compound4Args(argarray=(ArgOp4(40),)))
        with self.assertRaises(NFS4CodecError):
            roundtrip_res(Compound4Res(12345, b"", ()))

    def test_rejects_oversized_filehandle_and_bad_time(self):
        with self.assertRaises(NFS4CodecError):
            roundtrip_args(Compound4Args(argarray=(ArgOp4(const.OP_PUTFH, PutFh4Args(b"x" * 129)),)))
        with self.assertRaises(NFS4CodecError):
            roundtrip_args(
                Compound4Args(
                    argarray=(
                        ArgOp4(const.OP_VERIFY, Verify4Args(Fattr4({const.FATTR4_TIME_ACCESS: NfsTime4(0, 1_000_000_000)}))),
                    )
                )
            )

    def test_rejects_truncated_xdr_and_invalid_utf8(self):
        with self.assertRaises(EOFError):
            NFS4Unpacker(b"\0\0").unpack_compound_res()
        with self.assertRaises(UnicodeDecodeError):
            roundtrip_args(Compound4Args(tag=b"\xff"))


if __name__ == "__main__":
    unittest.main()
