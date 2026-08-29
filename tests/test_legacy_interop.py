import struct
from unittest import TestCase
from unittest.mock import patch

from pyNfsClient.const import MNT3ERR_NOENT, NFS3_PROCEDURE_NULL, NFS_PROGRAM, NFS_V3
from pyNfsClient.mount import Mount
from pyNfsClient.nfs3 import NFSv3
from pyNfsClient.portmap import Portmap
from pyNfsClient.rpc import RPC


class LegacyInteropTests(TestCase):
    def test_custom_rpcbind_port_is_preserved(self):
        portmap = Portmap("server", 5, 4000)
        self.assertEqual(portmap.port, 4000)

    def test_nfs3_null_uses_the_configured_authentication(self):
        auth = object()
        with patch.object(RPC, "request", return_value=b"") as request:
            self.assertEqual(NFSv3("server", 2049, 5, auth).null(), {"status": 0, "resok": None})
        request.assert_called_once_with(NFS_PROGRAM, NFS_V3, NFS3_PROCEDURE_NULL, auth=auth)

    def test_mount_paths_use_encoded_byte_length_and_padding(self):
        auth = object()
        mount = Mount("server", 20048, 5, auth)
        path = "/ré"
        encoded = path.encode()
        expected = struct.pack("!L", len(encoded)) + encoded + b"\0" * (-len(encoded) % 4)
        with patch.object(RPC, "request", return_value=struct.pack("!L", MNT3ERR_NOENT)) as request:
            self.assertEqual(mount.mnt(path)["status"], MNT3ERR_NOENT)
        self.assertEqual(request.call_args.kwargs["data"], expected)

        mount.path = path
        with patch.object(RPC, "request", return_value=b"") as request:
            mount.umnt()
        self.assertEqual(request.call_args.kwargs["data"], expected)
