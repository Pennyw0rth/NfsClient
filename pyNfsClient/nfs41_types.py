from dataclasses import dataclass

from . import nfs4_types as types40
from .nfs4_types import *
from . import nfs41_const as const


@dataclass(frozen=True, slots=True)
class CreatVerfAttr4:
    verifier: bytes
    attrs: Fattr4


@dataclass(frozen=True, slots=True)
class CreateHow4(types40.CreateHow4):
    createboth: CreatVerfAttr4 | None = None


@dataclass(frozen=True, slots=True)
class OpenClaim4(types40.OpenClaim4):
    delegate_stateid: Stateid4 | None = None


@dataclass(frozen=True, slots=True)
class OpenNoneDelegation4:
    why: int
    server_will_push_deleg: bool | None = None
    server_will_signal_avail: bool | None = None


@dataclass(frozen=True, slots=True)
class OpenDelegation4(types40.OpenDelegation4):
    none_ext: OpenNoneDelegation4 | None = None


@dataclass(frozen=True, slots=True)
class ClientOwner4:
    verifier: bytes
    ownerid: bytes


@dataclass(frozen=True, slots=True)
class ServerOwner4:
    minor_id: int
    major_id: bytes


@dataclass(frozen=True, slots=True)
class NfsImplId4:
    domain: bytes | str
    name: bytes | str
    date: NfsTime4


@dataclass(frozen=True, slots=True)
class StateProtect4A:
    how: int = const.SP4_NONE


@dataclass(frozen=True, slots=True)
class StateProtect4R:
    how: int = const.SP4_NONE


@dataclass(frozen=True, slots=True)
class BindConnToSession4Args:
    sessionid: bytes
    direction: int = const.CDFC4_FORE
    use_conn_in_rdma_mode: bool = False


@dataclass(frozen=True, slots=True)
class BindConnToSession4Res:
    sessionid: bytes
    direction: int
    use_conn_in_rdma_mode: bool


@dataclass(frozen=True, slots=True)
class ExchangeId4Args:
    client_owner: ClientOwner4
    flags: int = const.EXCHGID4_FLAG_USE_NON_PNFS
    state_protect: StateProtect4A = StateProtect4A()
    client_impl_id: tuple[NfsImplId4, ...] = ()


@dataclass(frozen=True, slots=True)
class ExchangeId4Res:
    clientid: int
    sequenceid: int
    flags: int
    state_protect: StateProtect4R
    server_owner: ServerOwner4
    server_scope: bytes
    server_impl_id: tuple[NfsImplId4, ...] = ()


@dataclass(frozen=True, slots=True)
class ChannelAttrs4:
    headerpadsize: int
    maxrequestsize: int
    maxresponsesize: int
    maxresponsesize_cached: int
    maxoperations: int
    maxrequests: int
    rdma_ird: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class CreateSession4Args:
    clientid: int
    sequence: int
    flags: int
    fore_chan_attrs: ChannelAttrs4
    back_chan_attrs: ChannelAttrs4
    cb_program: int = 0
    sec_parms: tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class CreateSession4Res:
    sessionid: bytes
    sequence: int
    flags: int
    fore_chan_attrs: ChannelAttrs4
    back_chan_attrs: ChannelAttrs4


@dataclass(frozen=True, slots=True)
class DestroySession4Args:
    sessionid: bytes


@dataclass(frozen=True, slots=True)
class Sequence4Args:
    sessionid: bytes
    sequenceid: int
    slotid: int = 0
    highest_slotid: int = 0
    cachethis: bool = True


@dataclass(frozen=True, slots=True)
class Sequence4Res:
    sessionid: bytes
    sequenceid: int
    slotid: int
    highest_slotid: int
    target_highest_slotid: int
    status_flags: int


@dataclass(frozen=True, slots=True)
class DestroyClientId4Args:
    clientid: int


@dataclass(frozen=True, slots=True)
class ReclaimComplete4Args:
    one_fs: bool = False
