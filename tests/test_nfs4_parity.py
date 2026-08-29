import inspect
from unittest import TestCase
from unittest.mock import patch

import pyNfsClient
from pyNfsClient import nfs4_const as const
from pyNfsClient import nfs4_types as types
from pyNfsClient.nfs3 import NFSv3
from pyNfsClient.nfs4 import NFSv4


COMMON_OPERATIONS = (
    "nfs_request",
    "null",
    "getattr",
    "setattr",
    "lookup",
    "access",
    "readlink",
    "read",
    "write",
    "create",
    "mkdir",
    "symlink",
    "mknod",
    "remove",
    "rmdir",
    "rename",
    "link",
    "readdir",
    "readdirplus",
    "fsstat",
    "fsinfo",
    "pathconf",
    "commit",
)


def compound(*results, status=const.NFS4_OK):
    return types.Compound4Res(status, b"", results)


class RawInterfaceParityTests(TestCase):
    def test_common_method_signatures_match_nfs3(self):
        for name in COMMON_OPERATIONS:
            with self.subTest(name=name):
                self.assertEqual(inspect.signature(getattr(NFSv4, name)), inspect.signature(getattr(NFSv3, name)))

    def test_facade_is_not_exported(self):
        self.assertFalse(hasattr(pyNfsClient, "NFSClient"))
        self.assertFalse(hasattr(pyNfsClient, "NFSClientError"))

    def test_getattr_uses_nfs3_response_shape(self):
        client = NFSv4("server")
        attributes = types.Fattr4(
            {
                const.FATTR4_TYPE: const.NF4REG,
                const.FATTR4_MODE: 0o640,
                const.FATTR4_NUMLINKS: 1,
                const.FATTR4_OWNER: b"1000",
                const.FATTR4_OWNER_GROUP: b"users@example.test",
                const.FATTR4_SIZE: 4,
                const.FATTR4_SPACE_USED: 8,
                const.FATTR4_FILEID: 7,
            }
        )
        with patch.object(
            client,
            "with_filehandle",
            return_value=compound(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes)),
        ):
            result = client.getattr(b"file")
        self.assertEqual(result["status"], const.NFS4_OK)
        self.assertEqual(result["attributes"]["uid"], 1000)
        self.assertEqual(result["attributes"]["gid"], "users@example.test")
        self.assertEqual(result["attributes"]["used"], 8)

    def test_lookup_tracks_open_provenance_and_matches_nfs3_shape(self):
        client = NFSv4("server")
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4REG})
        with patch.object(
            client,
            "with_filehandle",
            return_value=compound(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
                types.ResOp4(const.OP_LOOKUP, const.NFS4_OK),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"file"),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
            ),
        ):
            result = client.lookup(b"directory", "name")
        self.assertEqual(result["resok"]["object"], {"data": b"file"})
        self.assertTrue(result["resok"]["obj_attributes"]["present"])
        self.assertEqual(client.locations[b"file"], (b"directory", b"name"))

    def test_protocol_failure_is_returned_instead_of_raised(self):
        client = NFSv4("server")
        with patch.object(client, "with_filehandle", return_value=compound(types.ResOp4(const.OP_PUTFH, const.NFS4ERR_STALE), status=const.NFS4ERR_STALE)):
            result = client.access(b"stale", const.ACCESS4_READ)
        self.assertEqual(result["status"], const.NFS4ERR_STALE)
        self.assertIsNone(result["resok"])
        self.assertFalse(result["resfail"]["present"])

    def test_getattr_failure_retains_nfs3_default_field(self):
        client = NFSv4("server")
        with patch.object(client, "with_filehandle", return_value=compound(types.ResOp4(const.OP_PUTFH, const.NFS4ERR_STALE), status=const.NFS4ERR_STALE)):
            self.assertEqual(client.getattr(b"stale"), {"status": const.NFS4ERR_STALE, "attributes": None})

    def test_wcc_failure_does_not_add_resok(self):
        client = NFSv4("server")
        with patch.object(
            client,
            "with_filehandle",
            return_value=compound(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_GETATTR, const.NFS4ERR_ACCESS), status=const.NFS4ERR_ACCESS
            ),
        ):
            result = client.remove(b"directory", "file")
        self.assertNotIn("resok", result)
        self.assertIn("resfail", result)


if __name__ == "__main__":
    import unittest

    unittest.main()
