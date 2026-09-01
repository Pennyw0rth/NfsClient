import struct
import unittest
from unittest.mock import Mock, call, patch

from pyNfsClient import discover_minor_versions, probe_minor_version
from pyNfsClient import const as common_const
from pyNfsClient import nfs4_const as const
from pyNfsClient.nfs4_probe import interpret_probe_response
from pyNfsClient.rpc import RPCProtocolError
from pyNfsClient.xdrlib import Packer, Unpacker


def probe_response(status, results=(), tag=b""):
    packer = Packer()
    packer.pack_int(status)
    packer.pack_opaque(tag)
    packer.pack_uint(len(results))
    for operation, result_status in results:
        packer.pack_int(operation)
        packer.pack_int(result_status)
    return packer.get_buffer()


class NFSv4ProbeTests(unittest.TestCase):
    def test_probe_sends_state_free_putrootfh_compound_to_direct_port(self):
        rpc = Mock()
        rpc.request.return_value = probe_response(const.NFS4_OK, ((const.OP_PUTROOTFH, const.NFS4_OK),))
        auth = object()
        with patch("pyNfsClient.nfs4_probe.RPC", return_value=rpc) as rpc_class:
            self.assertTrue(probe_minor_version("nfs.example", 2, auth))

        rpc_class.assert_called_once_with("nfs.example", 2049, 5)
        rpc.connect.assert_called_once_with()
        rpc.disconnect.assert_called_once_with()
        program, version, procedure = rpc.request.call_args.args
        self.assertEqual((program, version, procedure), (const.NFS_PROGRAM, const.NFS_V4, const.NFS4_PROCEDURE_COMPOUND))
        self.assertIs(rpc.request.call_args.kwargs["auth"], auth)
        unpacker = Unpacker(rpc.request.call_args.kwargs["data"])
        self.assertEqual((unpacker.unpack_opaque(), unpacker.unpack_uint(), unpacker.unpack_uint(), unpacker.unpack_int()), (b"", 2, 1, const.OP_PUTROOTFH))
        unpacker.done()

    def test_probe_returns_false_only_for_empty_minor_version_mismatch(self):
        self.assertFalse(interpret_probe_response(probe_response(const.NFS4ERR_MINOR_VERS_MISMATCH)))
        with self.assertRaises(RPCProtocolError):
            interpret_probe_response(probe_response(const.NFS4ERR_MINOR_VERS_MISMATCH, ((const.OP_PUTROOTFH, const.NFS4ERR_MINOR_VERS_MISMATCH),)))

    def test_probe_accepts_recognized_minor_version_statuses(self):
        for status in (const.NFS4_OK, common_const.NFS4ERR_OP_NOT_IN_SESSION, const.NFS4ERR_WRONGSEC, 123456):
            with self.subTest(status=status):
                self.assertTrue(interpret_probe_response(probe_response(status, ((const.OP_PUTROOTFH, status),))))
        self.assertTrue(interpret_probe_response(probe_response(const.NFS4ERR_RESOURCE)))

    def test_probe_rejects_malformed_protocol_replies(self):
        malformed = (
            b"",
            probe_response(const.NFS4_OK),
            probe_response(const.NFS4_OK, ((const.OP_PUTROOTFH, const.NFS4_OK),), b"wrong-tag"),
            probe_response(const.NFS4_OK, ((const.OP_GETFH, const.NFS4_OK),)),
            probe_response(const.NFS4_OK, ((const.OP_PUTROOTFH, const.NFS4ERR_ACCESS),)),
            probe_response(const.NFS4_OK, ((const.OP_PUTROOTFH, const.NFS4_OK),)) + b"trailing",
        )
        for response in malformed:
            with self.subTest(response=response), self.assertRaises(RPCProtocolError):
                interpret_probe_response(response)

    def test_probe_disconnects_and_propagates_transport_errors(self):
        rpc = Mock()
        rpc.request.side_effect = TimeoutError("timed out")
        with patch("pyNfsClient.nfs4_probe.RPC", return_value=rpc):
            with self.assertRaises(TimeoutError):
                probe_minor_version("nfs.example", 1, port=3049, timeout=9)
        rpc.disconnect.assert_called_once_with()

    def test_discovery_probes_each_version_independently_in_descending_order(self):
        auth = object()
        with patch("pyNfsClient.nfs4_probe.probe_minor_version", side_effect=(True, False, True)) as probe:
            self.assertEqual(discover_minor_versions("nfs.example", auth, 3049, 9), (2, 0))
        self.assertEqual(probe.call_args_list, [call("nfs.example", 2, auth, 3049, 9), call("nfs.example", 1, auth, 3049, 9), call("nfs.example", 0, auth, 3049, 9)])

    def test_probe_rejects_invalid_minor_version_without_connecting(self):
        with patch("pyNfsClient.nfs4_probe.RPC") as rpc_class:
            for minor_version in (-1, 1 << 32, "1"):
                with self.subTest(minor_version=minor_version), self.assertRaises(ValueError):
                    probe_minor_version("nfs.example", minor_version)
        rpc_class.assert_not_called()


if __name__ == "__main__":
    unittest.main()
