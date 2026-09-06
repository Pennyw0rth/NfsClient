import threading
import unittest
from unittest.mock import Mock, call, patch

from pyNfsClient import nfs4_const as const40
from pyNfsClient import nfs41_const as const
from pyNfsClient import nfs41_types as types
from pyNfsClient import nfs42_const as const42
from pyNfsClient.nfs4_base import NFS4Error
from pyNfsClient.nfs4_pack import NFS4CodecError, NFS4Packer, NFS4Unpacker
from pyNfsClient.nfs41 import BACK_CHANNEL as OFFERED_BACK_CHANNEL, FORE_CHANNEL, NFSv41
from pyNfsClient.nfs41_pack import NFS41Packer, NFS41Unpacker, NFS42Packer, NFS42Unpacker
from pyNfsClient.nfs42 import NFSv42
from pyNfsClient.rpc import RPC, RPCProtocolError
from pyNfsClient.xdrlib import Packer


SESSION = b"session-id-00001"
VERIFIER = b"12345678"
CHANNEL = types.ChannelAttrs4(0, 1024 * 1024, 1024 * 1024, 64 * 1024, 16, 1)
BACK_CHANNEL = types.ChannelAttrs4(0, 1024 * 1024, 1024 * 1024, 64 * 1024, 8, 1)
EXCHANGE = types.ExchangeId4Res(7, 4, const.EXCHGID4_FLAG_USE_NON_PNFS, types.StateProtect4R(), types.ServerOwner4(3, b"server"), b"scope")
CREATED = types.CreateSession4Res(SESSION, 4, 0, CHANNEL, BACK_CHANNEL)


def response(*results, status=None, packer_class=NFS41Packer, tag=b""):
    if status is None:
        status = results[-1].status if results else const.NFS4_OK
    packer = packer_class()
    packer.pack_compound_res(types.Compound4Res(status, tag, results))
    return packer.get_buffer()


def sequence_result(sequenceid, status=const.NFS4_OK):
    result = types.Sequence4Res(SESSION, sequenceid, 0, 0, 0, 0) if status == const.NFS4_OK else None
    return types.ResOp4(const.OP_SEQUENCE, status, result)


def decode(payload, unpacker_class=NFS41Unpacker):
    unpacker = unpacker_class(payload)
    result = unpacker.unpack_compound_args()
    unpacker.done()
    return result


class MockNFSv41(NFSv41):
    def __init__(self, *responses, auth=None):
        super().__init__("server", auth=auth)
        self.responses = list(responses)
        self.calls = []

    def send_compound_payload(self, payload, auth, bind_session=False, cached=False):
        self.calls.append((payload, self.effective_auth(auth)))
        result = self.responses.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


class MockNFSv42(NFSv42):
    def __init__(self, *responses):
        super().__init__("server")
        self.responses = list(responses)
        self.calls = []

    def send_compound_payload(self, payload, auth, bind_session=False, cached=False):
        self.calls.append((payload, self.effective_auth(auth)))
        return self.responses.pop(0)


class NFSv41CodecTests(unittest.TestCase):
    def test_errors_use_known_later_minor_status_and_operation_names(self):
        self.assertEqual(str(NFS4Error(const.NFS4ERR_BADSESSION, const.OP_SEQUENCE)), "OP_SEQUENCE failed with NFS4ERR_BADSESSION")
        self.assertEqual(str(NFS4Error(const42.NFS4ERR_UNION_NOTSUPP)), "NFS4ERR_UNION_NOTSUPP")
        self.assertEqual(str(NFS4Error(123456, 654321)), "operation 654321 failed with 123456")

    def test_v41_open_constants_match_rfc8881(self):
        self.assertEqual((const.EXCLUSIVE4_1, const.OPEN4_SHARE_ACCESS_WANT_DELEG_MASK, const.OPEN4_SHARE_ACCESS_WANT_NO_DELEG), (3, 0xFF00, 0x0400))
        self.assertEqual((const.OPEN_DELEGATE_NONE_EXT, const.CLAIM_FH, const.CLAIM_DELEG_CUR_FH, const.CLAIM_DELEG_PREV_FH), (3, 4, 5, 6))
        self.assertEqual(tuple((name, getattr(const, name)) for name in ("WND4_NOT_WANTED", "WND4_CONTENTION", "WND4_RESOURCE", "WND4_NOT_SUPP_FTYPE", "WND4_WRITE_DELEG_NOT_SUPP_FTYPE", "WND4_NOT_SUPP_UPGRADE", "WND4_NOT_SUPP_DOWNGRADE", "WND4_CANCELLED", "WND4_IS_DIR")), (("WND4_NOT_WANTED", 0), ("WND4_CONTENTION", 1), ("WND4_RESOURCE", 2), ("WND4_NOT_SUPP_FTYPE", 3), ("WND4_WRITE_DELEG_NOT_SUPP_FTYPE", 4), ("WND4_NOT_SUPP_UPGRADE", 5), ("WND4_NOT_SUPP_DOWNGRADE", 6), ("WND4_CANCELLED", 7), ("WND4_IS_DIR", 8)))

    def test_exclusive41_create_how_matches_golden_wire_and_round_trips(self):
        value = types.CreateHow4(const.EXCLUSIVE4_1, createboth=types.CreatVerfAttr4(VERIFIER, types.Fattr4({const.FATTR4_MODE: 0o600})))
        packer = NFS41Packer()
        packer.pack_create_how(value)
        wire = bytes.fromhex("00000003 3132333435363738 00000002 00000000 00000002 00000004 00000180")
        self.assertEqual(packer.get_buffer(), wire)
        unpacker = NFS41Unpacker(wire)
        self.assertEqual(unpacker.unpack_create_how(), value)
        unpacker.done()
        with self.assertRaises(NFS4CodecError):
            packer = NFS41Packer()
            packer.pack_create_how(types.CreateHow4(const.EXCLUSIVE4_1, createboth=types.CreatVerfAttr4(b"short", types.Fattr4())))
        with self.assertRaises(NFS4CodecError):
            NFS4Packer().pack_create_how(value)
        with self.assertRaises(NFS4CodecError):
            NFS4Unpacker(wire).unpack_create_how()

    def test_filehandle_open_claims_match_golden_wire_and_round_trip(self):
        claims = (
            (types.OpenClaim4(const.CLAIM_FH), "00000004"),
            (types.OpenClaim4(const.CLAIM_DELEG_CUR_FH, delegate_stateid=types.Stateid4(7, b"abcdefghijkl")), "00000005 00000007 6162636465666768696a6b6c"),
            (types.OpenClaim4(const.CLAIM_DELEG_PREV_FH), "00000006"),
        )
        for value, golden in claims:
            with self.subTest(claim=value.claim):
                packer = NFS41Packer()
                packer.pack_open_claim(value)
                self.assertEqual(packer.get_buffer(), bytes.fromhex(golden))
                unpacker = NFS41Unpacker(bytes.fromhex(golden))
                self.assertEqual(unpacker.unpack_open_claim(), value)
                unpacker.done()
                with self.assertRaises(NFS4CodecError):
                    NFS4Packer().pack_open_claim(value)
                with self.assertRaises(NFS4CodecError):
                    NFS4Unpacker(bytes.fromhex(golden)).unpack_open_claim()
        with self.assertRaises(TypeError):
            NFS41Packer().pack_open_claim(types.OpenClaim4(const.CLAIM_DELEG_CUR_FH))

    def test_extended_no_delegation_matches_golden_wire_and_round_trips(self):
        golden_values = (
            (types.OpenDelegation4(const.OPEN_DELEGATE_NONE_EXT, none_ext=types.OpenNoneDelegation4(const.WND4_NOT_WANTED)), "00000003 00000000"),
            (types.OpenDelegation4(const.OPEN_DELEGATE_NONE_EXT, none_ext=types.OpenNoneDelegation4(const.WND4_CONTENTION, server_will_push_deleg=True)), "00000003 00000001 00000001"),
            (types.OpenDelegation4(const.OPEN_DELEGATE_NONE_EXT, none_ext=types.OpenNoneDelegation4(const.WND4_RESOURCE, server_will_signal_avail=False)), "00000003 00000002 00000000"),
        )
        for value, golden in golden_values:
            with self.subTest(reason=value.none_ext.why):
                packer = NFS41Packer()
                packer.pack_delegation(value)
                self.assertEqual(packer.get_buffer(), bytes.fromhex(golden))
        values = tuple(types.OpenDelegation4(const.OPEN_DELEGATE_NONE_EXT, none_ext=types.OpenNoneDelegation4(reason)) for reason in const.WHY_NO_DELEGATION4 - {const.WND4_CONTENTION, const.WND4_RESOURCE}) + tuple(types.OpenDelegation4(const.OPEN_DELEGATE_NONE_EXT, none_ext=types.OpenNoneDelegation4(const.WND4_CONTENTION, server_will_push_deleg=value)) for value in (False, True)) + tuple(types.OpenDelegation4(const.OPEN_DELEGATE_NONE_EXT, none_ext=types.OpenNoneDelegation4(const.WND4_RESOURCE, server_will_signal_avail=value)) for value in (False, True))
        for value in values:
            with self.subTest(reason=value.none_ext.why, push=value.none_ext.server_will_push_deleg, signal=value.none_ext.server_will_signal_avail):
                packer = NFS41Packer()
                packer.pack_delegation(value)
                unpacker = NFS41Unpacker(packer.get_buffer())
                self.assertEqual(unpacker.unpack_delegation(), value)
                unpacker.done()
        with self.assertRaises(EOFError):
            NFS41Unpacker(bytes.fromhex("00000003 00000001")).unpack_delegation()
        with self.assertRaises(NFS4CodecError):
            NFS41Unpacker(bytes.fromhex("00000003 00000009")).unpack_delegation()
        with self.assertRaises(NFS4CodecError):
            NFS4Packer().pack_delegation(golden_values[0][0])
        with self.assertRaises(NFS4CodecError):
            NFS4Unpacker(bytes.fromhex(golden_values[0][1])).unpack_delegation()

    def test_v41_and_v42_open_round_trip_with_want_no_delegation(self):
        argument = types.Open4Args(1, const.OPEN4_SHARE_ACCESS_READ | const.OPEN4_SHARE_ACCESS_WANT_NO_DELEG, const.OPEN4_SHARE_DENY_NONE, types.OpenOwner4(7, b"owner"), types.OpenFlag4(), types.OpenClaim4(const.CLAIM_FH))
        delegation = types.OpenDelegation4(const.OPEN_DELEGATE_NONE_EXT, none_ext=types.OpenNoneDelegation4(const.WND4_NOT_WANTED))
        result = types.Open4Res(types.Stateid4(2, b"abcdefghijkl"), types.ChangeInfo4(True, 1, 2), 0, types.Bitmap4(), delegation)
        for minor, packer_class, unpacker_class in ((1, NFS41Packer, NFS41Unpacker), (2, NFS42Packer, NFS42Unpacker)):
            with self.subTest(minor=minor):
                packer = packer_class()
                packer.pack_compound_args(types.Compound4Args(b"open", minor, (types.ArgOp4(const.OP_OPEN, argument),)))
                unpacker = unpacker_class(packer.get_buffer())
                self.assertEqual(unpacker.unpack_compound_args(), types.Compound4Args(b"open", minor, (types.ArgOp4(const.OP_OPEN, argument),)))
                unpacker.done()
                packer = packer_class()
                packer.pack_compound_res(types.Compound4Res(const.NFS4_OK, b"open", (types.ResOp4(const.OP_OPEN, const.NFS4_OK, result),)))
                unpacker = unpacker_class(packer.get_buffer())
                self.assertEqual(unpacker.unpack_compound_res(), types.Compound4Res(const.NFS4_OK, b"open", (types.ResOp4(const.OP_OPEN, const.NFS4_OK, result),)))
                unpacker.done()

    def test_required_operation_arguments_round_trip(self):
        owner = types.ClientOwner4(VERIFIER, b"client")
        operations = (
            types.ArgOp4(const.OP_BIND_CONN_TO_SESSION, types.BindConnToSession4Args(SESSION)),
            types.ArgOp4(const.OP_EXCHANGE_ID, types.ExchangeId4Args(owner)),
            types.ArgOp4(const.OP_CREATE_SESSION, types.CreateSession4Args(7, 4, 0, CHANNEL, CHANNEL)),
            types.ArgOp4(const.OP_DESTROY_SESSION, types.DestroySession4Args(SESSION)),
            types.ArgOp4(const.OP_SEQUENCE, types.Sequence4Args(SESSION, 1)),
            types.ArgOp4(const.OP_DESTROY_CLIENTID, types.DestroyClientId4Args(7)),
            types.ArgOp4(const.OP_RECLAIM_COMPLETE, types.ReclaimComplete4Args()),
            types.ArgOp4(const.OP_PUTROOTFH),
            types.ArgOp4(const.OP_GETFH),
        )
        packer = NFS41Packer()
        packer.pack_compound_args(types.Compound4Args(b"wire", 1, operations))
        self.assertEqual(decode(packer.get_buffer()), types.Compound4Args(b"wire", 1, operations))

    def test_required_operation_results_round_trip(self):
        results = (
            types.ResOp4(const.OP_BIND_CONN_TO_SESSION, const.NFS4_OK, types.BindConnToSession4Res(SESSION, const.CDFS4_FORE, False)),
            types.ResOp4(const.OP_EXCHANGE_ID, const.NFS4_OK, EXCHANGE),
            types.ResOp4(const.OP_CREATE_SESSION, const.NFS4_OK, CREATED),
            types.ResOp4(const.OP_DESTROY_SESSION, const.NFS4_OK),
            sequence_result(1),
            types.ResOp4(const.OP_DESTROY_CLIENTID, const.NFS4_OK),
            types.ResOp4(const.OP_RECLAIM_COMPLETE, const.NFS4_OK),
            types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"root"),
        )
        unpacker = NFS41Unpacker(response(*results))
        self.assertEqual(unpacker.unpack_compound_res(), types.Compound4Res(const.NFS4_OK, b"", results))
        unpacker.done()

    def test_profile_rejects_mandatory_not_to_implement_and_v42_optional_ops(self):
        for operation in (const.OP_OPEN_CONFIRM, const.OP_RENEW, const.OP_SETCLIENTID, const.OP_SETCLIENTID_CONFIRM, const.OP_RELEASE_LOCKOWNER):
            with self.subTest(operation=operation), self.assertRaises(NFS4CodecError):
                packer = NFS41Packer()
                packer.pack_compound_args(types.Compound4Args(b"", 1, (types.ArgOp4(operation),)))
        with self.assertRaises(NFS4CodecError):
            packer = NFS42Packer()
            packer.pack_compound_args(types.Compound4Args(b"", 2, (types.ArgOp4(59),)))

    def test_v42_uses_minor_two_with_the_session_wire_profile(self):
        operation = types.ArgOp4(const.OP_SEQUENCE, types.Sequence4Args(SESSION, 9))
        packer = NFS42Packer()
        packer.pack_compound_args(types.Compound4Args(b"v42", 2, (operation,)))
        self.assertEqual(decode(packer.get_buffer(), NFS42Unpacker), types.Compound4Args(b"v42", 2, (operation,)))
        self.assertTrue(issubclass(NFSv42, NFSv41))

        client = MockNFSv42(response(sequence_result(1), packer_class=NFS42Packer))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        client.compound(())
        self.assertEqual(decode(client.calls[0][0], NFS42Unpacker).minorversion, 2)

    def test_unknown_nfs_status_remains_structurally_decodable(self):
        packer = Packer()
        packer.pack_int(123456)
        packer.pack_opaque(b"")
        packer.pack_uint(1)
        packer.pack_int(const.OP_GETFH)
        packer.pack_int(123456)
        unpacker = NFS4Unpacker(packer.get_buffer())
        self.assertEqual(unpacker.unpack_compound_res(), types.Compound4Res(123456, b"", (types.ResOp4(const.OP_GETFH, 123456),)))
        unpacker.done()

    def test_nested_attribute_status_uses_the_minor_version_profile(self):
        attributes = types.Fattr4({const.FATTR4_RDATTR_ERROR: const.NFS4ERR_BADSESSION})
        result = types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes)
        unpacker = NFS41Unpacker(response(result))
        self.assertEqual(unpacker.unpack_compound_res().resarray[0].result, attributes)
        unpacker.done()

    def test_codec_rejects_callback_security_and_multi_element_optional_arrays(self):
        with self.assertRaises(NFS4CodecError):
            operation = types.ArgOp4(const.OP_CREATE_SESSION, types.CreateSession4Args(7, 4, 0, CHANNEL, CHANNEL, sec_parms=(object(),)))
            packer = NFS41Packer()
            packer.pack_compound_args(types.Compound4Args(b"", 1, (operation,)))
        with self.assertRaises(NFS4CodecError):
            implementations = (types.NfsImplId4(b"one", b"one", types.NfsTime4(0, 0)), types.NfsImplId4(b"two", b"two", types.NfsTime4(0, 0)))
            operation = types.ArgOp4(const.OP_EXCHANGE_ID, types.ExchangeId4Args(types.ClientOwner4(VERIFIER, b"client"), client_impl_id=implementations))
            packer = NFS41Packer()
            packer.pack_compound_args(types.Compound4Args(b"", 1, (operation,)))


class NFSv41SessionTests(unittest.TestCase):
    def test_establishment_uses_one_principal_and_sequences_reclaim_complete(self):
        client = MockNFSv41(
            response(types.ResOp4(const.OP_EXCHANGE_ID, const.NFS4_OK, EXCHANGE), tag=b"exchange-id"),
            response(types.ResOp4(const.OP_CREATE_SESSION, const.NFS4_OK, CREATED), tag=b"create-session"),
            response(sequence_result(1), types.ResOp4(const.OP_RECLAIM_COMPLETE, const.NFS4_OK), tag=b"reclaim-complete"),
        )
        auth = {"flavor": 1, "machine_name": b"client", "uid": 1000, "gid": 1000, "aux_gid": [10]}
        self.assertEqual(client.establish_session(b"client", VERIFIER, auth), SESSION)
        compounds = tuple(decode(payload) for payload, _ in client.calls)
        self.assertEqual(tuple(tuple(operation.op for operation in item.argarray) for item in compounds), ((const.OP_EXCHANGE_ID,), (const.OP_CREATE_SESSION,), (const.OP_SEQUENCE, const.OP_RECLAIM_COMPLETE)))
        self.assertEqual(compounds[2].argarray[0].arg, types.Sequence4Args(SESSION, 1, 0, 0, True))
        self.assertEqual(client.slot_sequenceid, 2)
        self.assertEqual(tuple(call_auth for _, call_auth in client.calls), (client.calls[0][1],) * 3)
        self.assertIsNot(client.calls[0][1], auth)

    def test_per_call_auth_snapshot_tracks_mutable_auth_sys_identity(self):
        client = MockNFSv41(
            response(sequence_result(1), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"one")),
            response(sequence_result(2), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"two")),
        )
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        auth = {"flavor": 1, "machine_name": b"client", "uid": 1000, "gid": 1000, "aux_gid": [10]}
        client.compound((client.getfh_op(),), auth=auth)
        auth["uid"] = 2000
        auth["gid"] = 3000
        auth["aux_gid"].append(20)
        client.compound((client.getfh_op(),), auth=auth)
        self.assertEqual((client.calls[0][1]["uid"], client.calls[0][1]["gid"], client.calls[0][1]["aux_gid"]), (1000, 1000, (10,)))
        self.assertEqual((client.calls[1][1]["uid"], client.calls[1][1]["gid"], client.calls[1][1]["aux_gid"]), (2000, 3000, (10, 20)))
        self.assertEqual(tuple(decode(payload).argarray[0].arg.sequenceid for payload, _ in client.calls), (1, 2))

    def test_sequence_advances_on_later_error_but_not_sequence_error(self):
        client = MockNFSv41(
            response(sequence_result(1), types.ResOp4(const.OP_ACCESS, const.NFS4ERR_ACCESS), status=const.NFS4ERR_ACCESS),
            response(sequence_result(2, const.NFS4ERR_DELAY), status=const.NFS4ERR_DELAY),
        )
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        client.compound((client.access_op(1),), check=False)
        self.assertEqual(client.slot_sequenceid, 2)
        client.compound((client.access_op(1),), check=False)
        self.assertEqual(client.slot_sequenceid, 2)
        self.assertTrue(client.session_broken)

    def test_all_sequence_errors_make_the_minimal_session_unusable(self):
        for status in (const.NFS4ERR_SEQ_MISORDERED, const.NFS4ERR_RETRY_UNCACHED_REP):
            with self.subTest(status=status):
                client = MockNFSv41(response(sequence_result(1, status), status=status))
                client.sessionid = SESSION
                client.fore_chan_attrs = CHANNEL
                client.compound((), check=False)
                self.assertEqual(client.slot_sequenceid, 1)
                self.assertTrue(client.session_broken)
                with self.assertRaises(RuntimeError):
                    client.compound(())

    def test_explicit_establishment_replaces_a_broken_session(self):
        client = MockNFSv41(
            response(types.ResOp4(const.OP_DESTROY_SESSION, const.NFS4_OK), tag=b"destroy-session"),
            response(types.ResOp4(const.OP_EXCHANGE_ID, const.NFS4_OK, EXCHANGE), tag=b"exchange-id"),
            response(types.ResOp4(const.OP_CREATE_SESSION, const.NFS4_OK, CREATED), tag=b"create-session"),
            response(sequence_result(1), types.ResOp4(const.OP_RECLAIM_COMPLETE, const.NFS4_OK), tag=b"reclaim-complete"),
        )
        client.sessionid = b"broken-session!!"
        client.fore_chan_attrs = CHANNEL
        client.session_broken = True
        self.assertEqual(client.establish_session(b"client", VERIFIER), SESSION)
        self.assertFalse(client.session_broken)
        self.assertEqual(client.slot_sequenceid, 2)

    def test_sequence_wraps_from_uint32_max_to_zero(self):
        client = MockNFSv41(response(sequence_result(0xFFFFFFFF)))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        client.slot_sequenceid = 0xFFFFFFFF
        client.compound(())
        self.assertEqual(client.slot_sequenceid, 0)

    def test_one_slot_serializes_concurrent_callers(self):
        client = MockNFSv41(response(sequence_result(1)), response(sequence_result(2)))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        entered = threading.Event()
        release = threading.Event()
        second_done = threading.Event()
        failures = []
        send = client.send_compound_payload

        def blocked_send(payload, auth, bind_session=False, cached=False):
            if not client.calls:
                entered.set()
                release.wait(1)
            return send(payload, auth, bind_session, cached)

        def issue(done=None):
            try:
                client.compound(())
            except Exception as e:
                failures.append(e)
            if done is not None:
                done.set()

        client.send_compound_payload = blocked_send
        first = threading.Thread(target=issue)
        second = threading.Thread(target=issue, args=(second_done,))
        first.start()
        self.assertTrue(entered.wait(1))
        second.start()
        self.assertFalse(second_done.wait(0.02))
        release.set()
        first.join(1)
        second.join(1)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(tuple(decode(payload).argarray[0].arg.sequenceid for payload, _ in client.calls), (1, 2))

    def test_unfinished_rpc_failures_retransmit_one_prepared_request(self):
        for failure in (TimeoutError("timeout"), ConnectionResetError("reset"), RPCProtocolError("truncated reply")):
            with self.subTest(failure=type(failure).__name__):
                client = NFSv41("server")
                prepared = Mock(call=b"rpc", reply_size=24, finished=False)
                client.prepare_request = Mock(return_value=prepared)
                client.send_prepared = Mock(side_effect=failure)
                client.retransmit = Mock(return_value=b"reply")
                client.bind_connection = Mock()
                client.sessionid = SESSION
                client.fore_chan_attrs = CHANNEL
                calls = Mock()
                with patch.object(RPC, "disconnect") as disconnect, patch.object(RPC, "connect") as connect:
                    calls.attach_mock(disconnect, "disconnect")
                    calls.attach_mock(prepared.reset_attempt, "reset_attempt")
                    calls.attach_mock(connect, "connect")
                    calls.attach_mock(client.bind_connection, "bind_connection")
                    calls.attach_mock(client.retransmit, "retransmit")
                    self.assertEqual(client.send_compound_payload(b"compound", None, bind_session=True), b"reply")
                client.send_prepared.assert_called_once_with(prepared)
                client.bind_connection.assert_called_once_with(auth=None)
                client.retransmit.assert_called_once_with(prepared)
                self.assertEqual(calls.mock_calls, [call.disconnect(client), call.reset_attempt(), call.connect(client), call.bind_connection(auth=None), call.retransmit(prepared)])

    def test_finished_rpc_failure_is_not_retransmitted(self):
        client = NFSv41("server")
        prepared = Mock(call=b"rpc", reply_size=24, finished=True)
        client.prepare_request = Mock(return_value=prepared)
        client.send_prepared = Mock(side_effect=RPCProtocolError("accepted RPC failure"))
        client.retransmit = Mock()
        client.bind_connection = Mock()
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        with patch.object(RPC, "disconnect") as disconnect, patch.object(RPC, "connect") as connect, self.assertRaises(RPCProtocolError):
            client.send_compound_payload(b"compound", None, bind_session=True)
        disconnect.assert_not_called()
        connect.assert_not_called()
        client.bind_connection.assert_not_called()
        client.retransmit.assert_not_called()

    def test_full_rpc_wire_sizes_enforce_negotiated_limits(self):
        client = NFSv41("server")
        prepared = Mock(call=b"1234", reply_size=4)
        client.prepare_request = Mock(return_value=prepared)
        client.send_prepared = Mock(return_value=b"")
        client.fore_chan_attrs = types.ChannelAttrs4(0, 3, 1024, 1024, 2, 1)
        with self.assertRaises(NFS4Error) as caught:
            client.send_compound_payload(b"payload", None)
        self.assertEqual(caught.exception.status, const.NFS4ERR_REQ_TOO_BIG)
        prepared.abort.assert_called_once_with()
        client.send_prepared.assert_not_called()

        prepared = Mock(call=b"1234", reply_size=4)
        client.prepare_request = Mock(return_value=prepared)
        client.send_prepared = Mock(return_value=b"")
        client.fore_chan_attrs = types.ChannelAttrs4(0, 1024, 3, 1024, 2, 1)
        with self.assertRaises(NFS4Error) as caught:
            client.send_compound_payload(b"payload", None)
        self.assertEqual(caught.exception.status, const.NFS4ERR_REP_TOO_BIG)

        prepared = Mock(call=b"1234", reply_size=4)
        client.prepare_request = Mock(return_value=prepared)
        client.send_prepared = Mock(return_value=b"")
        client.fore_chan_attrs = types.ChannelAttrs4(0, 1024, 1024, 3, 2, 1)
        with self.assertRaises(NFS4Error) as caught:
            client.send_compound_payload(b"payload", None, cached=True)
        self.assertEqual(caught.exception.status, const.NFS4ERR_REP_TOO_BIG_TO_CACHE)

    def test_raw_compound_is_restricted_and_callers_cannot_supply_sequence(self):
        client = MockNFSv41()
        with self.assertRaises(ValueError):
            client.compound_raw((client.putrootfh_op(),))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        with self.assertRaises(ValueError):
            client.compound((client.sequence_op(SESSION, 1),))

    def test_bind_connection_supports_only_the_negotiated_forechannel(self):
        bound = types.BindConnToSession4Res(SESSION, const.CDFS4_FORE, False)
        client = MockNFSv41(response(types.ResOp4(const.OP_BIND_CONN_TO_SESSION, const.NFS4_OK, bound), tag=b"bind-connection"))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        client.bind_connection()
        self.assertEqual(tuple(operation.op for operation in decode(client.calls[0][0]).argarray), (const.OP_BIND_CONN_TO_SESSION,))
        with self.assertRaises(ValueError):
            client.bind_connection(const.CDFC4_BACK)
        with self.assertRaises(ValueError):
            client.bind_connection(use_conn_in_rdma_mode=True)

        bound = types.BindConnToSession4Res(SESSION, const.CDFS4_BACK, False)
        client = MockNFSv41(response(types.ResOp4(const.OP_BIND_CONN_TO_SESSION, const.NFS4_OK, bound), tag=b"bind-connection"))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        with self.assertRaises(NFS4Error):
            client.bind_connection()

    def test_negotiated_operation_and_request_limits_are_enforced_locally(self):
        client = MockNFSv41()
        client.sessionid = SESSION
        client.fore_chan_attrs = types.ChannelAttrs4(0, 1, 1024, 1024, 1, 1)
        with self.assertRaises(NFS4Error) as caught:
            client.compound((client.getfh_op(),))
        self.assertEqual(caught.exception.status, const.NFS4ERR_TOO_MANY_OPS)
        client.fore_chan_attrs = types.ChannelAttrs4(0, 1, 1024, 1024, 2, 1)
        with self.assertRaises(NFS4Error) as caught:
            client.compound((client.getfh_op(),))
        self.assertEqual(caught.exception.status, const.NFS4ERR_REQ_TOO_BIG)
        self.assertFalse(client.session_broken)

    def test_negotiated_response_limit_and_malformed_sequence_break_session(self):
        oversized = response(sequence_result(1), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"root"))
        client = MockNFSv41(oversized)
        client.sessionid = SESSION
        client.fore_chan_attrs = types.ChannelAttrs4(0, 1024, len(oversized) - 1, 1024, 2, 1)
        with self.assertRaises(NFS4Error) as caught:
            client.compound((client.getfh_op(),))
        self.assertEqual(caught.exception.status, const.NFS4ERR_REP_TOO_BIG)
        self.assertTrue(client.session_broken)

        client = MockNFSv41(response(status=const.NFS4_OK))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        with self.assertRaises(NFS4Error):
            client.compound(())
        self.assertTrue(client.session_broken)

        invalid_slot = types.Sequence4Res(SESSION, 1, 1, 1, 1, 0)
        client = MockNFSv41(response(types.ResOp4(const.OP_SEQUENCE, const.NFS4_OK, invalid_slot)))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        with self.assertRaises(NFS4Error):
            client.compound(())
        self.assertEqual(client.slot_sequenceid, 1)
        self.assertTrue(client.session_broken)

        client = MockNFSv41(response(sequence_result(1), tag=b"wrong"))
        client.sessionid = SESSION
        client.fore_chan_attrs = CHANNEL
        with self.assertRaises(NFS4Error) as caught:
            client.compound((), tag=b"expected")
        self.assertEqual(caught.exception.status, const.NFS4ERR_BADXDR)
        self.assertTrue(client.session_broken)

    def test_sequence_accepts_negotiated_slot_bounds_but_still_requests_slot_zero(self):
        channels = types.ChannelAttrs4(0, 1024, 1024, 1024, 4, 4)
        sequence = types.Sequence4Res(SESSION, 1, 0, 3, 2, 0)
        client = MockNFSv41(response(types.ResOp4(const.OP_SEQUENCE, const.NFS4_OK, sequence)))
        client.sessionid = SESSION
        client.fore_chan_attrs = channels
        self.assertEqual((client.highest_slotid, client.target_highest_slotid), (0, 0))
        client.compound(())
        sent = decode(client.calls[0][0]).argarray[0].arg
        self.assertEqual((sent.slotid, sent.highest_slotid), (0, 0))
        self.assertEqual(client.slot_sequenceid, 2)
        self.assertEqual((client.highest_slotid, client.target_highest_slotid), (3, 2))
        self.assertFalse(client.session_broken)
        client.clear_session()
        self.assertEqual((client.highest_slotid, client.target_highest_slotid), (0, 0))

    def test_sequence_accepts_linux_dynamic_slot_expansion_while_using_slot_zero(self):
        channels = types.ChannelAttrs4(0, 1024, 1024, 1024, 4, 1)
        sequence = types.Sequence4Res(SESSION, 1, 0, 1, 1, 0)
        client = MockNFSv41(response(types.ResOp4(const.OP_SEQUENCE, const.NFS4_OK, sequence)))
        client.sessionid = SESSION
        client.fore_chan_attrs = channels
        client.compound(())
        sent = decode(client.calls[0][0]).argarray[0].arg
        self.assertEqual((sent.slotid, sent.highest_slotid), (0, 0))
        self.assertEqual(client.slot_sequenceid, 2)
        self.assertEqual((client.highest_slotid, client.target_highest_slotid), (1, 1))
        self.assertFalse(client.session_broken)

    def test_negotiation_accepts_server_role_but_rejects_invalid_role_and_backchannel(self):
        pnfs = types.ExchangeId4Res(7, 4, const.EXCHGID4_FLAG_USE_PNFS_MDS, types.StateProtect4R(), types.ServerOwner4(3, b"server"), b"scope")
        client = MockNFSv41(
            response(types.ResOp4(const.OP_EXCHANGE_ID, const.NFS4_OK, pnfs), tag=b"exchange-id"),
            response(types.ResOp4(const.OP_CREATE_SESSION, const.NFS4_OK, CREATED), tag=b"create-session"),
            response(sequence_result(1), types.ResOp4(const.OP_RECLAIM_COMPLETE, const.NFS4_OK), tag=b"reclaim-complete"),
        )
        self.assertEqual(client.establish_session(b"client", VERIFIER), SESSION)

        invalid_roles = types.ExchangeId4Res(7, 4, const.EXCHGID4_FLAG_USE_PNFS_MDS | const.EXCHGID4_FLAG_USE_NON_PNFS, types.StateProtect4R(), types.ServerOwner4(3, b"server"), b"scope")
        client = MockNFSv41(response(types.ResOp4(const.OP_EXCHANGE_ID, const.NFS4_OK, invalid_roles), tag=b"exchange-id"))
        with self.assertRaises(NFS4Error):
            client.establish_session(b"client", VERIFIER)

        backchannel = types.CreateSession4Res(SESSION, 4, const.CREATE_SESSION4_FLAG_CONN_BACK_CHAN, CHANNEL, CHANNEL)
        client = MockNFSv41(response(types.ResOp4(const.OP_EXCHANGE_ID, const.NFS4_OK, EXCHANGE), tag=b"exchange-id"), response(types.ResOp4(const.OP_CREATE_SESSION, const.NFS4_OK, backchannel), tag=b"create-session"))
        with self.assertRaises(NFS4Error):
            client.establish_session(b"client", VERIFIER)
        self.assertEqual((client.clientid, client.sessionid, client.session_broken), (7, SESSION, True))

        expanded = types.ChannelAttrs4(0, 1024 * 1024, 1024 * 1024, 64 * 1024, FORE_CHANNEL.maxoperations + 1, FORE_CHANNEL.maxrequests + 3)
        created = types.CreateSession4Res(SESSION, 4, 0, expanded, BACK_CHANNEL)
        client = MockNFSv41(
            response(types.ResOp4(const.OP_EXCHANGE_ID, const.NFS4_OK, EXCHANGE), tag=b"exchange-id"),
            response(types.ResOp4(const.OP_CREATE_SESSION, const.NFS4_OK, created), tag=b"create-session"),
            response(sequence_result(1), types.ResOp4(const.OP_RECLAIM_COMPLETE, const.NFS4_OK), tag=b"reclaim-complete"),
        )
        self.assertEqual(client.establish_session(b"client", VERIFIER), SESSION)
        sent = decode(client.calls[2][0]).argarray[0].arg
        self.assertEqual((sent.slotid, sent.highest_slotid), (0, 0))
        self.assertEqual(client.fore_chan_attrs, expanded)

    def test_backchannel_preserves_offered_operation_and_request_counts(self):
        for maxoperations, maxrequests in (
            (OFFERED_BACK_CHANNEL.maxoperations + 1, OFFERED_BACK_CHANNEL.maxrequests),
            (OFFERED_BACK_CHANNEL.maxoperations - 1, OFFERED_BACK_CHANNEL.maxrequests),
            (OFFERED_BACK_CHANNEL.maxoperations, OFFERED_BACK_CHANNEL.maxrequests + 1),
        ):
            with self.subTest(maxoperations=maxoperations, maxrequests=maxrequests):
                backchannel = types.ChannelAttrs4(0, 1024, 1024, 1024, maxoperations, maxrequests)
                created = types.CreateSession4Res(SESSION, 4, 0, CHANNEL, backchannel)
                client = MockNFSv41(response(types.ResOp4(const.OP_EXCHANGE_ID, const.NFS4_OK, EXCHANGE), tag=b"exchange-id"), response(types.ResOp4(const.OP_CREATE_SESSION, const.NFS4_OK, created), tag=b"create-session"))
                with self.assertRaises(NFS4Error):
                    client.establish_session(b"client", VERIFIER)
                self.assertEqual((client.clientid, client.sessionid, client.session_broken), (7, SESSION, True))


if __name__ == "__main__":
    unittest.main()
