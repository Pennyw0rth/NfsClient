import struct
import logging
from .rpc import RPC
from .pack import nfs_pro_v3Unpacker
from .const import MOUNT_PROGRAM, MOUNT_V3, MNT3_OK, MOUNTSTAT3, MNT3ERR_NOTSUPP

log = logging.getLogger(__package__)


class MountAccessError(Exception):
    pass


class Mount(RPC):
    program = MOUNT_PROGRAM
    program_version = MOUNT_V3

    def __init__(self, host, port, timeout, auth):
        super(Mount, self).__init__(host=host, port=port, timeout=timeout)
        self.path = None
        self.auth = auth

    def null(self, auth=None):
        log.debug(f"Mount NULL on {self.host}")
        super(Mount, self).request(self.program, self.program_version, 0, auth=auth if auth else self.auth)
        return {"status": MNT3_OK, "message": MOUNTSTAT3[MNT3_OK]}

    @staticmethod
    def pack_path(path):
        path = path.encode()
        return struct.pack("!L", len(path)) + path + b"\x00" * (-len(path) % 4)

    def mnt(self, path, auth=None):
        data = self.pack_path(path)

        log.debug(f"Do mount on {path}")
        data = super(Mount, self).request(self.program, self.program_version, 1, data=data,
                                          auth=auth if auth else self.auth)

        unpacker = nfs_pro_v3Unpacker(data)
        res = unpacker.unpack_mountres3()
        if res["status"] == MNT3_OK:
            self.path = path
        return res

    def umnt(self, auth=None):
        if not self.path:
            log.warning("No path mounted, cannot process umount.")
            return {"status": MNT3ERR_NOTSUPP, "message": MOUNTSTAT3[MNT3ERR_NOTSUPP]}
        log.debug(f"Do umount on {self.path}")
        super(Mount, self).request(self.program, self.program_version, 3, data=self.pack_path(self.path), auth=auth if auth else self.auth)

        return {"status": MNT3_OK, "message": MOUNTSTAT3[MNT3_OK]}

    def export(self):
        log.debug(f"Get mount export on {self.host}")
        export = super(Mount, self).request(self.program, self.program_version, 5)

        unpacker = nfs_pro_v3Unpacker(export)
        return unpacker.unpack_exports()
