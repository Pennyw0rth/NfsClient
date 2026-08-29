"""Small, typed value objects for the RFC 3530 wire protocol."""

from dataclasses import dataclass, field
from typing import Any, Mapping

from . import nfs4_const as const


@dataclass(frozen=True, slots=True)
class Bitmap4:
    words: tuple[int, ...] = ()

    @classmethod
    def from_bits(cls, *bits: int) -> "Bitmap4":
        if not bits:
            return cls()
        if min(bits) < 0:
            raise ValueError("bitmap bit numbers must be non-negative")
        words = [0] * (max(bits) // 32 + 1)
        for bit in bits:
            words[bit // 32] |= 1 << bit % 32
        return cls(tuple(words))

    def bits(self) -> tuple[int, ...]:
        return tuple(word_index * 32 + bit_index for word_index, word in enumerate(self.words) for bit_index in range(32) if word & 1 << bit_index)


@dataclass(frozen=True, slots=True)
class NfsTime4:
    seconds: int
    nseconds: int


@dataclass(frozen=True, slots=True)
class SetTime4:
    set_it: int = const.SET_TO_SERVER_TIME4
    time: NfsTime4 | None = None


@dataclass(frozen=True, slots=True)
class Fsid4:
    major: int
    minor: int


@dataclass(frozen=True, slots=True)
class FsLocation4:
    server: tuple[bytes | str, ...]
    rootpath: tuple[bytes | str, ...]


@dataclass(frozen=True, slots=True)
class FsLocations4:
    fs_root: tuple[bytes | str, ...]
    locations: tuple[FsLocation4, ...]


@dataclass(frozen=True, slots=True)
class NfsAce4:
    type: int
    flag: int
    access_mask: int
    who: bytes | str


@dataclass(frozen=True, slots=True)
class SpecData4:
    specdata1: int
    specdata2: int


@dataclass(frozen=True, slots=True)
class Fattr4:
    attributes: Mapping[int, Any] = field(default_factory=dict)

    @property
    def attrmask(self) -> Bitmap4:
        return Bitmap4.from_bits(*self.attributes)


@dataclass(frozen=True, slots=True)
class ChangeInfo4:
    atomic: bool
    before: int
    after: int


@dataclass(frozen=True, slots=True)
class ClientAddr4:
    r_netid: bytes | str
    r_addr: bytes | str


@dataclass(frozen=True, slots=True)
class CallbackClient4:
    cb_program: int
    cb_location: ClientAddr4


@dataclass(frozen=True, slots=True)
class Stateid4:
    seqid: int = 0
    other: bytes = b"\0" * const.NFS4_OTHER_SIZE

    def __post_init__(self) -> None:
        if len(self.other) != const.NFS4_OTHER_SIZE:
            raise ValueError("stateid other field must be 12 bytes")


@dataclass(frozen=True, slots=True)
class NfsClientId4:
    verifier: bytes
    id: bytes


@dataclass(frozen=True, slots=True)
class OpenOwner4:
    clientid: int
    owner: bytes


@dataclass(frozen=True, slots=True)
class LockOwner4:
    clientid: int
    owner: bytes


@dataclass(frozen=True, slots=True)
class CreateType4:
    type: int
    linkdata: bytes | str | None = None
    devdata: SpecData4 | None = None


@dataclass(frozen=True, slots=True)
class OpenToLockOwner4:
    open_seqid: int
    open_stateid: Stateid4
    lock_seqid: int
    lock_owner: LockOwner4


@dataclass(frozen=True, slots=True)
class ExistingLockOwner4:
    lock_stateid: Stateid4
    lock_seqid: int


@dataclass(frozen=True, slots=True)
class Locker4:
    new_lock_owner: bool
    open_owner: OpenToLockOwner4 | None = None
    lock_owner: ExistingLockOwner4 | None = None


@dataclass(frozen=True, slots=True)
class LockDenied4:
    offset: int
    length: int
    locktype: int
    owner: LockOwner4


@dataclass(frozen=True, slots=True)
class CreateHow4:
    mode: int
    createattrs: Fattr4 | None = None
    createverf: bytes | None = None


@dataclass(frozen=True, slots=True)
class OpenFlag4:
    opentype: int = const.OPEN4_NOCREATE
    how: CreateHow4 | None = None


@dataclass(frozen=True, slots=True)
class NfsModifiedLimit4:
    num_blocks: int
    bytes_per_block: int


@dataclass(frozen=True, slots=True)
class NfsSpaceLimit4:
    limitby: int
    filesize: int | None = None
    mod_blocks: NfsModifiedLimit4 | None = None


@dataclass(frozen=True, slots=True)
class OpenClaimDelegateCur4:
    delegate_stateid: Stateid4
    file: bytes | str


@dataclass(frozen=True, slots=True)
class OpenClaim4:
    claim: int
    file: bytes | str | None = None
    delegate_type: int | None = None
    delegate_cur_info: OpenClaimDelegateCur4 | None = None
    file_delegate_prev: bytes | str | None = None


@dataclass(frozen=True, slots=True)
class OpenReadDelegation4:
    stateid: Stateid4
    recall: bool
    permissions: NfsAce4


@dataclass(frozen=True, slots=True)
class OpenWriteDelegation4:
    stateid: Stateid4
    recall: bool
    space_limit: NfsSpaceLimit4
    permissions: NfsAce4


@dataclass(frozen=True, slots=True)
class OpenDelegation4:
    delegation_type: int = const.OPEN_DELEGATE_NONE
    read: OpenReadDelegation4 | None = None
    write: OpenWriteDelegation4 | None = None


@dataclass(frozen=True, slots=True)
class RpcSecGssInfo4:
    oid: bytes
    qop: int
    service: int


@dataclass(frozen=True, slots=True)
class SecInfo4:
    flavor: int
    flavor_info: RpcSecGssInfo4 | None = None


@dataclass(frozen=True, slots=True)
class Entry4:
    cookie: int
    name: bytes | str
    attrs: Fattr4


@dataclass(frozen=True, slots=True)
class Access4Args:
    access: int


@dataclass(frozen=True, slots=True)
class Close4Args:
    seqid: int
    open_stateid: Stateid4


@dataclass(frozen=True, slots=True)
class Commit4Args:
    offset: int
    count: int


@dataclass(frozen=True, slots=True)
class Create4Args:
    objtype: CreateType4
    objname: bytes | str
    createattrs: Fattr4 = field(default_factory=Fattr4)


@dataclass(frozen=True, slots=True)
class DelegPurge4Args:
    clientid: int


@dataclass(frozen=True, slots=True)
class DelegReturn4Args:
    deleg_stateid: Stateid4


@dataclass(frozen=True, slots=True)
class GetAttr4Args:
    attr_request: Bitmap4


@dataclass(frozen=True, slots=True)
class Link4Args:
    newname: bytes | str


@dataclass(frozen=True, slots=True)
class Lock4Args:
    locktype: int
    reclaim: bool
    offset: int
    length: int
    locker: Locker4


@dataclass(frozen=True, slots=True)
class LockT4Args:
    locktype: int
    offset: int
    length: int
    owner: LockOwner4


@dataclass(frozen=True, slots=True)
class LockU4Args:
    locktype: int
    seqid: int
    lock_stateid: Stateid4
    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class Lookup4Args:
    objname: bytes | str


@dataclass(frozen=True, slots=True)
class NVerify4Args:
    obj_attributes: Fattr4


@dataclass(frozen=True, slots=True)
class Open4Args:
    seqid: int
    share_access: int
    share_deny: int
    owner: OpenOwner4
    openhow: OpenFlag4
    claim: OpenClaim4


@dataclass(frozen=True, slots=True)
class OpenAttr4Args:
    createdir: bool


@dataclass(frozen=True, slots=True)
class OpenConfirm4Args:
    open_stateid: Stateid4
    seqid: int


@dataclass(frozen=True, slots=True)
class OpenDowngrade4Args:
    open_stateid: Stateid4
    seqid: int
    share_access: int
    share_deny: int


@dataclass(frozen=True, slots=True)
class PutFh4Args:
    object: bytes


@dataclass(frozen=True, slots=True)
class Read4Args:
    stateid: Stateid4
    offset: int
    count: int


@dataclass(frozen=True, slots=True)
class ReadDir4Args:
    cookie: int
    cookieverf: bytes
    dircount: int
    maxcount: int
    attr_request: Bitmap4


@dataclass(frozen=True, slots=True)
class Remove4Args:
    target: bytes | str


@dataclass(frozen=True, slots=True)
class Rename4Args:
    oldname: bytes | str
    newname: bytes | str


@dataclass(frozen=True, slots=True)
class Renew4Args:
    clientid: int


@dataclass(frozen=True, slots=True)
class SecInfo4Args:
    name: bytes | str


@dataclass(frozen=True, slots=True)
class SetAttr4Args:
    stateid: Stateid4
    obj_attributes: Fattr4


@dataclass(frozen=True, slots=True)
class SetClientId4Args:
    client: NfsClientId4
    callback: CallbackClient4
    callback_ident: int


@dataclass(frozen=True, slots=True)
class SetClientIdConfirm4Args:
    clientid: int
    setclientid_confirm: bytes


@dataclass(frozen=True, slots=True)
class Verify4Args:
    obj_attributes: Fattr4


@dataclass(frozen=True, slots=True)
class Write4Args:
    stateid: Stateid4
    offset: int
    stable: int
    data: bytes


@dataclass(frozen=True, slots=True)
class ReleaseLockOwner4Args:
    lock_owner: LockOwner4


@dataclass(frozen=True, slots=True)
class Access4Res:
    supported: int
    access: int


@dataclass(frozen=True, slots=True)
class Commit4Res:
    writeverf: bytes


@dataclass(frozen=True, slots=True)
class Create4Res:
    cinfo: ChangeInfo4
    attrset: Bitmap4


@dataclass(frozen=True, slots=True)
class Link4Res:
    cinfo: ChangeInfo4


@dataclass(frozen=True, slots=True)
class Open4Res:
    stateid: Stateid4
    cinfo: ChangeInfo4
    rflags: int
    attrset: Bitmap4
    delegation: OpenDelegation4 = field(default_factory=OpenDelegation4)


@dataclass(frozen=True, slots=True)
class Read4Res:
    eof: bool
    data: bytes


@dataclass(frozen=True, slots=True)
class ReadDir4Res:
    cookieverf: bytes
    entries: tuple[Entry4, ...]
    eof: bool


@dataclass(frozen=True, slots=True)
class Rename4Res:
    source_cinfo: ChangeInfo4
    target_cinfo: ChangeInfo4


@dataclass(frozen=True, slots=True)
class SetAttr4Res:
    attrsset: Bitmap4


@dataclass(frozen=True, slots=True)
class SetClientId4Res:
    clientid: int
    setclientid_confirm: bytes


@dataclass(frozen=True, slots=True)
class Write4Res:
    count: int
    committed: int
    writeverf: bytes


@dataclass(frozen=True, slots=True)
class ArgOp4:
    op: int
    arg: Any = None


@dataclass(frozen=True, slots=True)
class ResOp4:
    op: int
    status: int
    result: Any = None


@dataclass(frozen=True, slots=True)
class Compound4Args:
    tag: bytes | str = b""
    minorversion: int = const.NFS4_MINOR_VERSION
    argarray: tuple[ArgOp4, ...] = ()


@dataclass(frozen=True, slots=True)
class Compound4Res:
    status: int
    tag: bytes
    resarray: tuple[ResOp4, ...]


# Familiar rpcgen-style aliases retained for callers that use RFC names.
bitmap4 = Bitmap4
nfstime4 = NfsTime4
settime4 = SetTime4
fsid4 = Fsid4
specdata4 = SpecData4
fattr4 = Fattr4
stateid4 = Stateid4
nfs_argop4 = ArgOp4
nfs_resop4 = ResOp4
COMPOUND4args = Compound4Args
COMPOUND4res = Compound4Res
