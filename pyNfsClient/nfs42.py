from . import nfs42_const as const
from .nfs41 import NFSv41
from .nfs41_pack import NFS42Packer, NFS42Unpacker


class NFSv42(NFSv41):
    minor_version = const.NFS4_MINOR_VERSION
    legal_operations = const.NFS4_OPERATIONS
    packer_class = NFS42Packer
    unpacker_class = NFS42Unpacker


__all__ = ("NFSv42",)
