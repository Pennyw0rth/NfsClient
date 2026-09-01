import inspect
import unittest
from unittest.mock import Mock, patch

import pyNfsClient
from pyNfsClient import ClientIdentity, NFSv40, NFSv4Protocol
from pyNfsClient import nfs4_const as const
from pyNfsClient import nfs4_types as types
from pyNfsClient.nfs4_base import DEFAULT_ATTRIBUTES, DIRECTORY_ATTRIBUTES, NFS4Error, NFS4UncertainError
from pyNfsClient.nfs4_pack import NFS4CodecError, NFS4Packer, NFS4Unpacker
from pyNfsClient.rpc import RPC


STATEID = types.Stateid4(1, b"stateid-one!")
VERIFIER = b"12345678"
CHANGE = types.ChangeInfo4(True, 1, 2)

def response(*results, status=const.NFS4_OK, tag=b""):
    packer = NFS4Packer()
    packer.pack_compound_res(types.Compound4Res(status, tag, results))
    return packer.get_buffer()


class MockNFSv40(NFSv40):
    def __init__(self, *responses):
        super().__init__("server")
        self.responses = list(responses)
        self.calls = []

    def send_compound_payload(self, args, auth):
        self.calls.append((const.NFS4_PROCEDURE_COMPOUND, args, self.effective_auth(auth)))
        request_unpacker = NFS4Unpacker(args)
        request = request_unpacker.unpack_compound_args()
        request_unpacker.done()
        response_data = self.responses.pop(0)
        if isinstance(response_data, BaseException):
            raise response_data
        response_unpacker = NFS4Unpacker(response_data)
        result = response_unpacker.unpack_compound_res()
        response_unpacker.done()
        packer = NFS4Packer()
        packer.pack_compound_res(types.Compound4Res(result.status, request.tag, result.resarray))
        return packer.get_buffer()


class NFSv4RawTests(unittest.TestCase):
    def test_only_explicit_minor_client_is_exported(self):
        self.assertIn("NFSv40", pyNfsClient.__all__)
        self.assertNotIn("NFSv4", pyNfsClient.__all__)
        self.assertFalse(hasattr(pyNfsClient, "NFSv4"))

    def test_nfsv40_implements_raw_protocol(self):
        self.assertTrue(issubclass(NFSv40, NFSv4Protocol))
        with self.assertRaises(TypeError):
            NFSv4Protocol("server")
        self.assertEqual(inspect.signature(NFSv40), inspect.Signature((
            inspect.Parameter("host", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            inspect.Parameter("port", inspect.Parameter.POSITIONAL_OR_KEYWORD, default=2049),
            inspect.Parameter("timeout", inspect.Parameter.POSITIONAL_OR_KEYWORD, default=5),
            inspect.Parameter("auth", inspect.Parameter.POSITIONAL_OR_KEYWORD, default=None),
            inspect.Parameter("client_identity", inspect.Parameter.KEYWORD_ONLY, default=None),
        )))

    def test_client_identity_validates_wire_fields(self):
        identity = ClientIdentity(b"netexec", b"12345678")
        self.assertEqual(identity.owner_id, b"netexec")
        with self.assertRaises(ValueError):
            ClientIdentity(b"", b"12345678")
        with self.assertRaises(ValueError):
            ClientIdentity(b"netexec", b"short")

    def test_operation_builders_return_rfc_operations(self):
        client = NFSv40("server")
        operations = (
            client.putrootfh_op(),
            client.lookup_op(b"folder"),
            client.getfh_op(),
            client.getattr_op(types.Bitmap4.from_bits(const.FATTR4_TYPE)),
        )
        self.assertEqual(tuple(operation.op for operation in operations), (const.OP_PUTROOTFH, const.OP_LOOKUP, const.OP_GETFH, const.OP_GETATTR))

    def test_attribute_builders_default_empty_and_expose_candidate_masks(self):
        client = NFSv40("server")
        self.assertEqual(client.getattr_op().arg.attr_request, types.Bitmap4())
        self.assertEqual(client.readdir_op().arg.attr_request, types.Bitmap4())
        self.assertTrue(DEFAULT_ATTRIBUTES.bits())
        self.assertGreater(set(DIRECTORY_ATTRIBUTES.bits()), set(DEFAULT_ATTRIBUTES.bits()))
        supported = types.Bitmap4.from_bits(const.FATTR4_TYPE, const.FATTR4_MODE, const.FATTR4_FILEHANDLE)
        requested = types.Bitmap4.from_bits(*(set(DIRECTORY_ATTRIBUTES.bits()) & set(supported.bits())))
        self.assertEqual(set(requested.bits()), {const.FATTR4_TYPE, const.FATTR4_MODE, const.FATTR4_FILEHANDLE})

    def test_netexec_controls_open_read_close_compounds(self):
        client = MockNFSv40(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opened"),
            ),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4_OK, STATEID)),
        )
        request = client.prepare_open(b"file")
        client.compound((client.putfh_op(b"parent"), request, client.getfh_op()))
        self.assertEqual(request.state.filehandle, b"opened")
        close = client.prepare_close(request.state)
        client.compound((client.putfh_op(request.state.filehandle), close))
        unpacked = []
        for _, data, _ in client.calls:
            unpacker = NFS4Unpacker(data)
            unpacked.append(unpacker.unpack_compound_args())
            unpacker.done()
        self.assertEqual(tuple(operation.op for operation in unpacked[2].argarray), (const.OP_PUTFH, const.OP_OPEN, const.OP_GETFH))
        self.assertEqual(tuple(operation.op for operation in unpacked[3].argarray), (const.OP_PUTFH, const.OP_CLOSE))
        self.assertEqual(client.open_owner().seqid, 2)

    def test_open_state_is_partitioned_by_auth_sys_principal(self):
        first_auth = {"flavor": 1, "machine_name": "client", "uid": 1000, "gid": 1000, "aux_gid": []}
        second_auth = {"flavor": 1, "machine_name": "client", "uid": 2000, "gid": 2000, "aux_gid": []}
        client = MockNFSv40(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"first"),
            ),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(types.Stateid4(2, b"stateid-two!"), CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"second"),
            ),
        )
        first = client.prepare_open(b"file", auth=first_auth)
        client.compound((client.putfh_op(b"parent"), first, client.getfh_op()), auth=first_auth)
        second = client.prepare_open(b"file", auth=second_auth)
        client.compound((client.putfh_op(b"parent"), second, client.getfh_op()), auth=second_auth)

        self.assertNotEqual(first.owner.owner, second.owner.owner)
        self.assertNotEqual(first.state.principal, second.state.principal)
        self.assertEqual((first.owner.seqid, second.owner.seqid), (1, 1))
        with self.assertRaises(ValueError):
            client.prepare_close(first.state, auth=second_auth)

    def test_prepared_state_rejects_a_different_execution_principal(self):
        first_auth = {"flavor": 1, "machine_name": "client", "uid": 1000, "gid": 1000, "aux_gid": []}
        second_auth = {**first_auth, "uid": 2000}
        client = MockNFSv40(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
        )
        opened = client.prepare_open(b"file", auth=first_auth)

        with self.assertRaises(ValueError):
            client.compound((client.putfh_op(b"parent"), opened, client.getfh_op()), auth=second_auth)
        self.assertFalse(opened.owner.inflight)
        self.assertEqual(client.prepare_open(b"file", auth=first_auth).operation.arg.seqid, 0)

    def test_open_requires_getfh_before_another_filehandle_operation(self):
        client = MockNFSv40(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
        )
        opened = client.prepare_open(b"file")

        with self.assertRaises(ValueError):
            client.compound((client.putfh_op(b"parent"), opened, client.putfh_op(b"replacement"), client.getfh_op()))
        self.assertFalse(opened.owner.inflight)
        self.assertEqual(client.prepare_open(b"file").operation.arg.seqid, 0)

    def test_open_packing_failure_releases_the_owner(self):
        client = MockNFSv40(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
        )
        opened = client.prepare_open(b"file", claim=types.OpenClaim4(99))

        with self.assertRaises(NFS4CodecError):
            client.compound((client.putfh_op(b"parent"), opened, client.getfh_op()))
        self.assertFalse(opened.owner.inflight)
        self.assertEqual(client.prepare_open(b"file").operation.arg.seqid, 0)

    def test_repeated_open_returns_distinct_references_and_closes_out_of_order(self):
        client = MockNFSv40(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opened"),
            ),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(types.Stateid4(2, STATEID.other), CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opened"),
            ),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN_DOWNGRADE, const.NFS4_OK, types.Stateid4(3, STATEID.other))),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4_OK, types.Stateid4(4, STATEID.other))),
        )
        first = client.prepare_open(b"file")
        client.compound((client.putfh_op(b"parent"), first, client.getfh_op()))
        second = client.prepare_open(b"file", share_access=const.OPEN4_SHARE_ACCESS_WRITE)
        client.compound((client.putfh_op(b"parent"), second, client.getfh_op()))

        self.assertIsNot(first.state, second.state)
        self.assertIs(first.state.state, second.state.state)
        self.assertEqual(first.state.stateid.seqid, 2)
        self.assertEqual(first.state.share_access, const.OPEN4_SHARE_ACCESS_BOTH)
        self.assertEqual([(item.access, item.deny) for item in first.state.opens], [(const.OPEN4_SHARE_ACCESS_READ, const.OPEN4_SHARE_DENY_NONE), (const.OPEN4_SHARE_ACCESS_WRITE, const.OPEN4_SHARE_DENY_NONE)])
        self.assertEqual(len(first.owner.opened), 1)

        downgrade = client.prepare_close(first.state)
        self.assertEqual(downgrade.operation.op, const.OP_OPEN_DOWNGRADE)
        self.assertEqual(downgrade.operation.arg.share_access, const.OPEN4_SHARE_ACCESS_WRITE)
        client.compound((client.putfh_op(first.state.filehandle), downgrade))
        self.assertTrue(first.state.closed)
        self.assertFalse(second.state.closed)
        self.assertEqual(second.state.stateid.seqid, 3)
        self.assertEqual([(item.access, item.deny) for item in second.state.opens], [(const.OPEN4_SHARE_ACCESS_WRITE, const.OPEN4_SHARE_DENY_NONE)])
        self.assertEqual(len(first.owner.opened), 1)

        close = client.prepare_close(second.state)
        self.assertEqual(close.operation.op, const.OP_CLOSE)
        client.compound((client.putfh_op(second.state.filehandle), close))
        self.assertEqual(first.owner.seqid, 4)
        self.assertEqual(first.owner.opened, [])
        self.assertTrue(second.state.closed)
        self.assertEqual(first.state.opens, [])

    def test_open_without_an_immediate_filehandle_replays_exact_payload(self):
        incomplete_results = (
            (
                "failed",
                response(
                    types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                    types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                    types.ResOp4(const.OP_GETFH, const.NFS4ERR_MOVED),
                    status=const.NFS4ERR_MOVED,
                ),
            ),
            (
                "missing",
                response(
                    types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                    types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                ),
            ),
        )
        for name, incomplete_response in incomplete_results:
            with self.subTest(name=name):
                client = MockNFSv40(
                    response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
                    response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
                    incomplete_response,
                    response(
                        types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                        types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                        types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opened"),
                    ),
                )
                opened = client.prepare_open(b"file")
                if name == "missing":
                    with self.assertRaises(NFS4Error):
                        client.compound((client.putfh_op(b"parent"), opened, client.getfh_op()), tag=b"open", check=False)
                else:
                    client.compound((client.putfh_op(b"parent"), opened, client.getfh_op()), tag=b"open", check=False)

                self.assertIsNone(opened.state)
                self.assertTrue(opened.owner.inflight)
                self.assertIsNotNone(opened.owner.pending)
                self.assertEqual(opened.owner.seqid, 0)
                original_payload = client.calls[2][1]

                with patch.object(RPC, "disconnect"), patch.object(RPC, "connect"):
                    client.retry_pending(check=False)

                self.assertEqual(client.calls[3][1], original_payload)
                self.assertIsNone(opened.owner.pending)
                self.assertFalse(opened.owner.inflight)
                self.assertEqual(opened.owner.seqid, 1)
                self.assertEqual(opened.state.filehandle, b"opened")

    def test_uncertain_open_confirm_finalizes_the_original_open(self):
        prepared_rpc = Mock(finished=False)
        client = MockNFSv40(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, const.OPEN4_RESULT_CONFIRM, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opened"),
            ),
            NFS4UncertainError(prepared_rpc),
        )
        opened = client.prepare_open(b"file")

        with self.assertRaises(NFS4UncertainError):
            client.compound((client.putfh_op(b"parent"), opened, client.getfh_op()), tag=b"open")

        self.assertIsNone(opened.state)
        self.assertIsNotNone(opened.owner.pending)
        self.assertIs(opened.owner.pending.operations[1].prepared_open, opened)
        self.assertEqual(opened.owner.seqid, 1)
        confirm_response = response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN_CONFIRM, const.NFS4_OK, types.Stateid4(2, STATEID.other)), tag=b"open-confirm")
        with patch.object(client, "retransmit", return_value=confirm_response), patch.object(RPC, "disconnect"), patch.object(RPC, "connect"):
            client.retry_pending()

        self.assertIsNone(opened.owner.pending)
        self.assertEqual(opened.owner.seqid, 2)
        self.assertEqual(opened.state.filehandle, b"opened")
        self.assertIs(opened.owner.opened[0], opened.state.state)

    def test_finished_pending_retry_falls_back_to_a_fresh_rpc(self):
        client = NFSv40("server")
        client.client = object()
        client.clientid = 7
        client.open_owner_name = b"owner"
        owner = client.open_owner()
        opened = client.prepare_open(b"file")
        prepared_rpc = Mock(finished=False)
        with patch.object(client, "prepare_request", return_value=prepared_rpc), patch.object(client, "send_prepared", side_effect=TimeoutError), patch.object(client, "retransmit", side_effect=TimeoutError), patch.object(RPC, "disconnect"), patch.object(RPC, "connect"):
            with self.assertRaises(NFS4UncertainError):
                client.compound((client.putfh_op(b"parent"), opened, client.getfh_op()), tag=b"open")
        self.assertIsNotNone(owner.pending)
        prepared_rpc.finished = True
        prepared_rpc.reset_attempt.side_effect = RuntimeError("request is finished")

        with patch.object(RPC, "disconnect"), patch.object(RPC, "connect"):
            with self.assertRaisesRegex(RuntimeError, "request is finished"):
                client.retry_pending()

        self.assertEqual(client.clientid, 7)
        self.assertIs(owner.pending.request, None)
        retry_response = response(
            types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
            types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
            types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opened"),
            tag=b"open",
        )
        with patch.object(client, "send_compound_payload", return_value=retry_response), patch.object(RPC, "disconnect"), patch.object(RPC, "connect"):
            client.retry_pending()
        self.assertIsNone(owner.pending)
        self.assertEqual(opened.state.filehandle, b"opened")

    def test_moved_does_not_advance_open_owner_seqid(self):
        client = MockNFSv40(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(7, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN, const.NFS4ERR_MOVED), status=const.NFS4ERR_MOVED),
        )
        opened = client.prepare_open(b"file")
        client.compound((client.putfh_op(b"parent"), opened, client.getfh_op()), check=False)

        self.assertEqual(opened.owner.seqid, 0)
        retry = client.prepare_open(b"file")
        self.assertEqual(retry.operation.arg.seqid, 0)

    def test_timeout_reconnects_and_replays_the_retained_rpc_request(self):
        client = NFSv40("server")
        client.client = object()
        prepared = Mock(finished=False)
        with patch.object(client, "prepare_request", return_value=prepared), patch.object(client, "send_prepared", side_effect=TimeoutError), patch.object(client, "retransmit", return_value=response(types.ResOp4(const.OP_PUTROOTFH, const.NFS4_OK), tag=b"root")) as retransmit, patch.object(RPC, "disconnect") as disconnect, patch.object(RPC, "connect") as connect:
            result = client.compound((client.putrootfh_op(),), tag=b"root")

        self.assertEqual(result.status, const.NFS4_OK)
        prepared.reset_attempt.assert_called_once_with()
        retransmit.assert_called_once_with(prepared)
        disconnect.assert_called_once_with(client)
        connect.assert_called_once_with(client)

    def test_unresolved_open_blocks_owner_until_exact_retry_completes(self):
        client = NFSv40("server")
        client.client = object()
        client.clientid = 7
        client.open_owner_name = b"owner"
        owner = client.open_owner()
        opened = client.prepare_open(b"file")
        prepared = Mock(finished=False)
        retry_response = response(
            types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
            types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4(), types.OpenDelegation4(const.OPEN_DELEGATE_NONE))),
            types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opened"),
            tag=b"open",
        )
        with patch.object(client, "prepare_request", return_value=prepared), patch.object(client, "send_prepared", side_effect=TimeoutError), patch.object(client, "retransmit", side_effect=TimeoutError), patch.object(RPC, "disconnect"), patch.object(RPC, "connect"):
            with self.assertRaises(NFS4UncertainError):
                client.compound((client.putfh_op(b"parent"), opened, client.getfh_op()), tag=b"open")
        self.assertIsNotNone(owner.pending)
        with self.assertRaises(RuntimeError):
            client.prepare_open(b"other")

        with patch.object(client, "retransmit", return_value=retry_response), patch.object(RPC, "disconnect"), patch.object(RPC, "connect"):
            client.retry_pending()
        self.assertIsNone(owner.pending)
        self.assertEqual(opened.state.filehandle, b"opened")
        self.assertEqual(owner.seqid, 1)


if __name__ == "__main__":
    unittest.main()
