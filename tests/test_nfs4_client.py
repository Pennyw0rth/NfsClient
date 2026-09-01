import unittest
from unittest.mock import Mock, patch

from pyNfsClient import nfs4_const as const
from pyNfsClient import nfs4_types as types
from pyNfsClient.const import DONT_CHANGE, EXCLUSIVE, GUARDED, SET_TO_CLIENT_TIME
from pyNfsClient.nfs4 import LockedFile4, NFS4Error, NFSv4, OpenFile4
from pyNfsClient.nfs4_pack import NFS4Packer, NFS4Unpacker


STATEID = types.Stateid4(1, b"stateid-one!")
NEXT_STATEID = types.Stateid4(2, b"stateid-two!")
DELEG_STATEID = types.Stateid4(3, b"deleg-state!")
VERIFIER = b"12345678"
CHANGE = types.ChangeInfo4(True, 1, 2)


def encode_response(response):
    packer = NFS4Packer()
    packer.pack_compound_res(response)
    return packer.get_buffer()


def decode_call(data):
    unpacker = NFS4Unpacker(data)
    call = unpacker.unpack_compound_args()
    unpacker.done()
    return call


def response(*results, status=const.NFS4_OK, tag=b""):
    return encode_response(types.Compound4Res(status, tag, results))


class MockNFSv4(NFSv4):
    def __init__(self, *responses):
        super().__init__("nfs.example", timeout=1)
        self.responses = list(responses)
        self.calls = []

    def nfs_request(self, procedure, args, auth):
        self.calls.append((procedure, args, self.effective_auth(auth)))
        return self.responses.pop(0)


class NFSv4ClientTests(unittest.TestCase):
    def test_direct_port_and_null(self):
        client = MockNFSv4(b"")
        self.assertEqual(client.port, 2049)
        client.null()
        self.assertEqual(client.calls, [(const.NFS4_PROCEDURE_NULL, b"", None)])

    def test_compound_encodes_and_decodes_operations(self):
        client = MockNFSv4(response(types.ResOp4(const.OP_PUTROOTFH, const.NFS4_OK), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"root-handle")))
        self.assertEqual(client.operation_result(client.with_root(client.getfh_op()), const.OP_GETFH), b"root-handle")
        self.assertEqual(client.calls[0][0], const.NFS4_PROCEDURE_COMPOUND)
        self.assertEqual(tuple(operation.op for operation in decode_call(client.calls[0][1]).argarray), (const.OP_PUTROOTFH, const.OP_GETFH))

    def test_all_forechannel_operation_builders(self):
        lock_owner = types.LockOwner4(7, b"lock-owner")
        operations = (
            NFSv4.access_op(const.ACCESS4_READ),
            NFSv4.close_op(0, STATEID),
            NFSv4.commit_op(),
            NFSv4.create_op(types.CreateType4(const.NF4DIR), b"directory"),
            NFSv4.delegpurge_op(7),
            NFSv4.delegreturn_op(DELEG_STATEID),
            NFSv4.getattr_op(),
            NFSv4.getfh_op(),
            NFSv4.link_op(b"link"),
            NFSv4.lock_op(const.WRITE_LT, False, 0, 1, types.Locker4(False, lock_owner=types.ExistingLockOwner4(STATEID, 0))),
            NFSv4.lockt_op(const.READ_LT, 0, 1, lock_owner),
            NFSv4.locku_op(const.WRITE_LT, 1, STATEID, 0, 1),
            NFSv4.lookup_op(b"name"),
            NFSv4.lookupp_op(),
            NFSv4.nverify_op(types.Fattr4()),
            NFSv4.open_op(
                0,
                const.OPEN4_SHARE_ACCESS_READ,
                const.OPEN4_SHARE_DENY_NONE,
                types.OpenOwner4(7, b"open-owner"),
                types.OpenFlag4(),
                types.OpenClaim4(const.CLAIM_NULL, file=b"file"),
            ),
            NFSv4.openattr_op(),
            NFSv4.open_confirm_op(STATEID, 1),
            NFSv4.open_downgrade_op(STATEID, 1, const.OPEN4_SHARE_ACCESS_READ, const.OPEN4_SHARE_DENY_NONE),
            NFSv4.putfh_op(b"filehandle"),
            NFSv4.putpubfh_op(),
            NFSv4.putrootfh_op(),
            NFSv4.read_op(STATEID),
            NFSv4.readdir_op(),
            NFSv4.readlink_op(),
            NFSv4.remove_op(b"file"),
            NFSv4.rename_op(b"old", b"new"),
            NFSv4.renew_op(7),
            NFSv4.restorefh_op(),
            NFSv4.savefh_op(),
            NFSv4.secinfo_op(b"file"),
            NFSv4.setattr_op(STATEID, types.Fattr4()),
            NFSv4.setclientid_op(types.NfsClientId4(VERIFIER, b"client"), types.CallbackClient4(0, types.ClientAddr4(b"", b""))),
            NFSv4.setclientid_confirm_op(7, VERIFIER),
            NFSv4.verify_op(types.Fattr4()),
            NFSv4.write_op(STATEID, 0, b"data"),
            NFSv4.release_lockowner_op(lock_owner),
        )
        self.assertEqual(tuple(operation.op for operation in operations), tuple(range(const.OP_ACCESS, const.OP_RELEASE_LOCKOWNER + 1)))

    def test_checked_status_error_and_unchecked_response(self):
        encoded = response(types.ResOp4(const.OP_PUTFH, const.NFS4ERR_STALE), status=const.NFS4ERR_STALE)
        with self.assertRaises(NFS4Error) as caught:
            MockNFSv4(encoded).with_filehandle(b"stale", NFSv4.getfh_op())
        self.assertEqual(caught.exception.status, const.NFS4ERR_STALE)
        self.assertEqual(caught.exception.operation, const.OP_PUTFH)
        self.assertEqual(MockNFSv4(encoded).with_filehandle(b"stale", NFSv4.getfh_op(), check=False).status, const.NFS4ERR_STALE)

    def test_compound_rejects_inconsistent_or_short_success_results(self):
        with self.assertRaises(NFS4Error) as inconsistent:
            MockNFSv4(response(types.ResOp4(const.OP_PUTROOTFH, const.NFS4ERR_ACCESS), status=const.NFS4_OK)).with_root(check=False)
        self.assertEqual(inconsistent.exception.status, const.NFS4ERR_BADXDR)

        with self.assertRaises(NFS4Error) as short:
            MockNFSv4(response(types.ResOp4(const.OP_PUTROOTFH, const.NFS4_OK))).with_root(NFSv4.getfh_op(), check=False)
        self.assertEqual(short.exception.status, const.NFS4ERR_BADXDR)

        with self.assertRaises(NFS4Error) as continued:
            MockNFSv4(response(types.ResOp4(const.OP_PUTROOTFH, const.NFS4ERR_ACCESS), types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"invalid"))).with_root(
                NFSv4.getfh_op(), check=False
            )
        self.assertEqual(continued.exception.status, const.NFS4ERR_BADXDR)

    def test_saved_and_current_filehandles(self):
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_SAVEFH, const.NFS4_OK),
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_RENAME, const.NFS4_OK, types.Rename4Res(CHANGE, CHANGE)),
            )
        )
        client.with_filehandles(b"target", b"source", client.rename_op(b"old", b"new"))
        operations = decode_call(client.calls[0][1]).argarray
        self.assertEqual(tuple(operation.op for operation in operations), (22, 32, 22, 29))
        self.assertEqual(operations[0].arg.object, b"source")
        self.assertEqual(operations[2].arg.object, b"target")

    def test_setclientid_uses_inert_callback_and_confirms(self):
        client = MockNFSv4(
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(77, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
        )
        self.assertEqual(client.establish_client(b"client", VERIFIER, b"owner"), 77)
        setclientid = decode_call(client.calls[0][1]).argarray[0].arg
        self.assertEqual(setclientid.callback.cb_program, 0)
        self.assertEqual(setclientid.callback.cb_location, types.ClientAddr4(b"", b""))
        self.assertEqual(decode_call(client.calls[1][1]).argarray[0].arg, types.SetClientIdConfirm4Args(77, VERIFIER))
        self.assertEqual(client.open_owner, b"owner")
        self.assertEqual(client.open_seqid, 0)

    def test_default_setclientid_names_are_unique_per_instance(self):
        setclientid_response = response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(77, VERIFIER)))
        confirm_response = response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK))
        with patch("pyNfsClient.nfs4.secrets.token_hex", side_effect=("first-instance", "second-instance")):
            first = MockNFSv4(setclientid_response, confirm_response)
            second = MockNFSv4(setclientid_response, confirm_response)
        first.establish_client(verifier=VERIFIER)
        second.establish_client(verifier=VERIFIER)
        self.assertNotEqual(first.client_name, second.client_name)
        self.assertTrue(first.client_name.endswith(b":first-instance"))
        self.assertTrue(second.client_name.endswith(b":second-instance"))

    def test_open_confirm_delegreturn_and_close_sequence(self):
        delegation = types.OpenDelegation4(
            const.OPEN_DELEGATE_READ,
            read=types.OpenReadDelegation4(DELEG_STATEID, False, types.NfsAce4(const.ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, const.ACE4_GENERIC_READ, b"OWNER@")),
        )
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, const.OPEN4_RESULT_CONFIRM, types.Bitmap4(), delegation)),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opened"),
            ),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN_CONFIRM, const.NFS4_OK, NEXT_STATEID)),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_DELEGRETURN, const.NFS4_OK)),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4_OK, STATEID)),
        )
        client.clientid = 77
        client.open_owner = b"owner"
        opened_file = client.open_file(b"parent", b"file")
        self.assertEqual(opened_file.filehandle, b"opened")
        self.assertEqual(opened_file.stateid, NEXT_STATEID)
        self.assertEqual(decode_call(client.calls[0][1]).argarray[1].arg.seqid, 0)
        self.assertEqual(decode_call(client.calls[1][1]).argarray[1].arg.seqid, 1)
        self.assertEqual(decode_call(client.calls[2][1]).argarray[1].arg.deleg_stateid, DELEG_STATEID)
        self.assertEqual(client.close_file(opened_file), STATEID)
        self.assertEqual(decode_call(client.calls[3][1]).argarray[1].arg.seqid, 2)
        self.assertEqual(client.open_seqid, 3)

    def test_open_sequence_advances_on_processed_errors_only(self):
        client = MockNFSv4(
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN, const.NFS4ERR_ACCESS), status=const.NFS4ERR_ACCESS)
        )
        client.clientid = 77
        client.open_owner = b"owner"
        with self.assertRaises(NFS4Error):
            client.open_file(b"parent", b"file")
        self.assertEqual(client.open_seqid, 1)

        client = MockNFSv4(
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN, const.NFS4ERR_BAD_SEQID), status=const.NFS4ERR_BAD_SEQID)
        )
        client.clientid = 77
        client.open_owner = b"owner"
        with self.assertRaises(NFS4Error):
            client.open_file(b"parent", b"file")
        self.assertEqual(client.open_seqid, 0)

        client = MockNFSv4(
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_OPEN, const.NFS4ERR_MOVED), status=const.NFS4ERR_MOVED)
        )
        client.clientid = 77
        client.open_owner = b"owner"
        with self.assertRaises(NFS4Error):
            client.open_file(b"parent", b"file")
        self.assertEqual(client.open_seqid, 0)

    def test_open_state_is_isolated_by_authentication_principal(self):
        auth = {
            "flavor": const.AUTH_SYS,
            "machine_name": "client.example",
            "uid": 1000,
            "gid": 100,
            "aux_gid": [101],
        }
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4())),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"file"),
            ),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(NEXT_STATEID, CHANGE, 0, types.Bitmap4())),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"file"),
            ),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4_OK, STATEID)),
        )
        client.auth = auth
        client.clientid = 77
        client.open_owner = b"owner"
        client.locations[b"file"] = (b"parent", b"file")

        first = client.ensure_open(b"file", const.OPEN4_SHARE_ACCESS_READ)
        first_auth = dict(auth)
        first_auth["aux_gid"] = list(auth["aux_gid"])
        auth["uid"] = 2000
        second = client.ensure_open(b"file", const.OPEN4_SHARE_ACCESS_READ)

        first_state = client.open_state(first_auth, create=False)
        second_state = client.open_state(create=False)
        self.assertIsNot(first_state, second_state)
        self.assertEqual(first_state.auth["uid"], 1000)
        self.assertEqual(first_state.opened[b"file"], first)
        self.assertEqual(second_state.opened[b"file"], second)
        self.assertEqual((first_state.seqid, second_state.seqid), (1, 1))
        first_open = decode_call(client.calls[0][1]).argarray[1].arg
        second_open = decode_call(client.calls[1][1]).argarray[1].arg
        self.assertEqual((first_open.seqid, second_open.seqid), (0, 0))
        self.assertEqual((first_open.owner.owner, second_open.owner.owner), (b"owner", b"owner:1"))
        self.assertEqual(client.ensure_open(b"file", const.OPEN4_SHARE_ACCESS_READ, first_auth), first)
        self.assertTrue(client.close_handle(b"file", first_auth))
        self.assertNotIn(b"file", first_state.opened)
        self.assertIn(b"file", second_state.opened)
        self.assertEqual(decode_call(client.calls[2][1]).argarray[1].arg.seqid, 1)

    def test_object_authentication_overrides_have_separate_open_state(self):
        client = MockNFSv4()
        client.clientid = 77
        client.open_owner = b"owner"
        first_auth = object()
        second_auth = object()

        self.assertIsNot(client.require_client(first_auth), client.require_client(second_auth))
        self.assertNotEqual(client.require_client(first_auth).owner, client.require_client(second_auth).owner)

    def test_disconnect_closes_saved_auth_none_state_after_default_auth_changes(self):
        client = MockNFSv4(response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4_OK, NEXT_STATEID)))
        client.clientid = 77
        client.open_owner = b"owner"
        client.opened[b"file"] = OpenFile4(b"file", STATEID, const.OPEN4_SHARE_ACCESS_READ, const.OPEN4_SHARE_DENY_NONE)
        client.auth = {
            "flavor": const.AUTH_SYS,
            "machine_name": "client.example",
            "uid": 2000,
            "gid": 200,
            "aux_gid": [],
        }
        client.client = Mock()

        client.disconnect()

        self.assertIsNone(client.calls[0][2])
        self.assertEqual(decode_call(client.calls[0][1]).argarray[1].arg.seqid, 0)

    def test_remove_closes_only_the_calling_principals_state(self):
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4DIR})
        first_auth = {
            "flavor": const.AUTH_SYS,
            "machine_name": "client.example",
            "uid": 1000,
            "gid": 100,
            "aux_gid": [],
        }
        second_auth = {**first_auth, "uid": 2000}
        client = MockNFSv4(
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4_OK, NEXT_STATEID)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
                types.ResOp4(const.OP_REMOVE, const.NFS4_OK, CHANGE),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
            ),
        )
        client.auth = first_auth
        client.clientid = 77
        client.open_owner = b"owner"
        client.opened[b"file"] = OpenFile4(b"file", STATEID, const.OPEN4_SHARE_ACCESS_READ, const.OPEN4_SHARE_DENY_NONE)
        client.open_state(second_auth).opened[b"file"] = OpenFile4(b"file", NEXT_STATEID, const.OPEN4_SHARE_ACCESS_READ, const.OPEN4_SHARE_DENY_NONE)
        client.locations[b"file"] = (b"parent", b"name")

        self.assertEqual(client.remove(b"parent", b"name", second_auth)["status"], const.NFS4_OK)

        self.assertIn(b"file", client.open_state(first_auth).opened)
        self.assertNotIn(b"file", client.open_state(second_auth).opened)
        self.assertEqual(client.auth_identity(client.calls[0][2]), client.auth_identity(second_auth))
        self.assertEqual(client.auth_identity(client.calls[1][2]), client.auth_identity(second_auth))

    def test_ensure_open_rejects_a_replaced_path_handle(self):
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4REG})
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4())),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"replacement"),
            ),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4_OK, NEXT_STATEID)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
                types.ResOp4(const.OP_READ, const.NFS4_OK, types.Read4Res(True, b"original data")),
            ),
        )
        client.clientid = 77
        client.open_owner = b"owner"
        client.locations[b"original"] = (b"parent", b"name")

        self.assertEqual(client.read(b"original")["resok"]["data"], b"original data")

        self.assertNotIn(b"original", client.locations)
        self.assertNotIn(b"original", client.opened)
        self.assertNotIn(b"replacement", client.opened)
        close_call = decode_call(client.calls[1][1]).argarray
        read_call = decode_call(client.calls[2][1]).argarray
        self.assertEqual(close_call[0].arg.object, b"replacement")
        self.assertEqual(read_call[0].arg.object, b"original")
        self.assertEqual(read_call[2].arg.stateid, types.Stateid4())

    def test_close_failure_retains_open_state_for_retry(self):
        client = MockNFSv4(response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4ERR_DELAY), status=const.NFS4ERR_DELAY))
        client.clientid = 77
        client.open_owner = b"owner"
        client.opened[b"file"] = OpenFile4(b"file", STATEID, const.OPEN4_SHARE_ACCESS_READ, const.OPEN4_SHARE_DENY_NONE)

        with self.assertRaises(NFS4Error):
            client.close_handle(b"file")
        self.assertIn(b"file", client.opened)

    def test_lock_renew_unlock_and_release_helpers(self):
        client = MockNFSv4(
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_LOCK, const.NFS4_OK, STATEID)),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_LOCKU, const.NFS4_OK, NEXT_STATEID)),
            response(types.ResOp4(const.OP_RENEW, const.NFS4_OK)),
            response(types.ResOp4(const.OP_RELEASE_LOCKOWNER, const.NFS4_OK)),
        )
        client.clientid = 77
        client.open_owner = b"open-owner"
        locked_file = client.acquire_lock(OpenFile4(b"opened", STATEID, const.OPEN4_SHARE_ACCESS_BOTH, const.OPEN4_SHARE_DENY_NONE), b"lock-owner")
        self.assertEqual(locked_file.stateid, STATEID)
        lock_arguments = decode_call(client.calls[0][1]).argarray[1].arg
        self.assertTrue(lock_arguments.locker.new_lock_owner)
        self.assertEqual(lock_arguments.locker.open_owner.open_seqid, 0)
        self.assertEqual(lock_arguments.locker.open_owner.lock_seqid, 0)
        unlocked_file = client.unlock(locked_file)
        self.assertEqual(unlocked_file.stateid, NEXT_STATEID)
        self.assertEqual(unlocked_file.seqid, 2)
        self.assertEqual(decode_call(client.calls[1][1]).argarray[1].arg.seqid, 1)
        client.renew_client()
        client.release_lock_owner(b"lock-owner")
        self.assertEqual(decode_call(client.calls[2][1]).argarray[0].op, const.OP_RENEW)
        self.assertEqual(decode_call(client.calls[3][1]).argarray[0].arg.lock_owner, types.LockOwner4(77, b"lock-owner"))

    def test_unlock_advances_sequence_after_processed_error(self):
        client = MockNFSv4(
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_LOCKU, const.NFS4ERR_DELAY), status=const.NFS4ERR_DELAY),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_LOCKU, const.NFS4_OK, NEXT_STATEID)),
        )
        locked_file = LockedFile4(b"file", STATEID, types.LockOwner4(77, b"owner"))

        with self.assertRaises(NFS4Error):
            client.unlock(locked_file)
        unlocked_file = client.unlock(locked_file)

        self.assertEqual(decode_call(client.calls[0][1]).argarray[1].arg.seqid, 1)
        self.assertEqual(decode_call(client.calls[1][1]).argarray[1].arg.seqid, 2)
        self.assertEqual(unlocked_file.seqid, 3)

    def test_unlock_does_not_advance_sequence_after_retry_error(self):
        for status in (const.NFS4ERR_BAD_SEQID, const.NFS4ERR_MOVED):
            with self.subTest(status=status):
                client = MockNFSv4(
                    response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_LOCKU, status), status=status),
                    response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_LOCKU, const.NFS4_OK, NEXT_STATEID)),
                )
                locked_file = LockedFile4(b"file", STATEID, types.LockOwner4(77, b"owner"))

                with self.assertRaises(NFS4Error):
                    client.unlock(locked_file)
                client.unlock(locked_file)

                self.assertEqual(decode_call(client.calls[0][1]).argarray[1].arg.seqid, 1)
                self.assertEqual(decode_call(client.calls[1][1]).argarray[1].arg.seqid, 1)

    def test_readdirplus_uses_cookie_and_verifier(self):
        first_entry = types.Entry4(11, b"first", types.Fattr4({const.FATTR4_FILEHANDLE: b"one"}))
        second_entry = types.Entry4(12, b"second", types.Fattr4({const.FATTR4_FILEHANDLE: b"two"}))
        directory_attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4DIR})
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, directory_attributes),
                types.ResOp4(const.OP_READDIR, const.NFS4_OK, types.ReadDir4Res(VERIFIER, (first_entry,), False)),
            ),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, directory_attributes),
                types.ResOp4(const.OP_READDIR, const.NFS4_OK, types.ReadDir4Res(VERIFIER, (second_entry,), True)),
            ),
        )
        first = client.readdirplus(b"directory")
        second = client.readdirplus(b"directory", 11, VERIFIER)
        self.assertEqual(first["resok"]["reply"]["entries"][0]["name"], b"first")
        self.assertFalse(first["resok"]["reply"]["eof"])
        self.assertEqual(second["resok"]["reply"]["entries"][0]["name"], b"second")
        self.assertTrue(second["resok"]["reply"]["eof"])
        self.assertEqual(decode_call(client.calls[1][1]).argarray[2].arg.cookie, 11)
        self.assertEqual(decode_call(client.calls[1][1]).argarray[2].arg.cookieverf, VERIFIER)

    def test_readdir_uses_zero_initial_verifier_and_minimal_attributes(self):
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, types.Fattr4({const.FATTR4_TYPE: const.NF4DIR})),
                types.ResOp4(const.OP_READDIR, const.NFS4_OK, types.ReadDir4Res(VERIFIER, (), True)),
            )
        )
        client.readdir(b"directory")
        arguments = decode_call(client.calls[0][1]).argarray[2].arg
        self.assertEqual(arguments.cookieverf, b"\0" * const.NFS4_VERIFIER_SIZE)
        self.assertEqual(arguments.attr_request.bits(), (const.FATTR4_FILEID,))

    def test_lookup_path_returns_opaque_handle_and_attributes(self):
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4DIR})
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTROOTFH, const.NFS4_OK),
                types.ResOp4(const.OP_LOOKUP, const.NFS4_OK),
                types.ResOp4(const.OP_LOOKUP, const.NFS4_OK),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"opaque\0handle"),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
            )
        )
        self.assertEqual(client.lookup_path("/one/two"), (b"opaque\0handle", attributes))
        self.assertEqual(
            tuple(operation.arg.objname for operation in decode_call(client.calls[0][1]).argarray if operation.op == const.OP_LOOKUP), (b"one", b"two")
        )

    def test_common_create_write_read_commit_close_workflow(self):
        directory_attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4DIR, const.FATTR4_SIZE: 1})
        file_attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4REG, const.FATTR4_SIZE: 4})
        client = MockNFSv4(
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_GETATTR, const.NFS4_OK, directory_attributes)),
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(77, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4())),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"file"),
            ),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_GETATTR, const.NFS4_OK, file_attributes)),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_GETATTR, const.NFS4_OK, directory_attributes)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, file_attributes),
                types.ResOp4(const.OP_WRITE, const.NFS4_OK, types.Write4Res(4, const.FILE_SYNC4, VERIFIER)),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, file_attributes),
            ),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, file_attributes),
                types.ResOp4(const.OP_READ, const.NFS4_OK, types.Read4Res(True, b"data")),
            ),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, file_attributes),
                types.ResOp4(const.OP_COMMIT, const.NFS4_OK, types.Commit4Res(VERIFIER)),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, file_attributes),
            ),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_CLOSE, const.NFS4_OK, NEXT_STATEID)),
        )

        created = client.create(b"directory", b"file", GUARDED, mode=0o600)
        self.assertEqual(created["resok"]["obj"]["handle"]["data"], b"file")
        self.assertEqual(tuple(operation.op for operation in decode_call(client.calls[3][1]).argarray), (const.OP_PUTFH, const.OP_OPEN, const.OP_GETFH))
        self.assertEqual(client.write(b"file", 0, 4, b"data", const.FILE_SYNC4)["resok"]["count"], 4)
        self.assertEqual(client.read(b"file")["resok"]["data"], b"data")
        self.assertEqual(client.commit(b"file")["resok"]["verf"], VERIFIER)
        self.assertTrue(client.close_handle(b"file"))
        self.assertEqual(client.open_seqid, 2)

    def test_setattr_encodes_client_mtime(self):
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4REG})
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
                types.ResOp4(const.OP_SETATTR, const.NFS4_OK, types.SetAttr4Res(types.Bitmap4.from_bits(const.FATTR4_TIME_MODIFY_SET))),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
            )
        )

        self.assertEqual(client.setattr(b"file", atime_flag=DONT_CHANGE, mtime_flag=SET_TO_CLIENT_TIME, mtime_s=123, mtime_us=456)["status"], const.NFS4_OK)
        self.assertEqual(
            decode_call(client.calls[0][1]).argarray[2].arg.obj_attributes.attributes[const.FATTR4_TIME_MODIFY_SET],
            types.SetTime4(const.SET_TO_CLIENT_TIME4, types.NfsTime4(123, 456)),
        )

    def test_write_success_survives_trailing_getattr_failure(self):
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4REG})
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
                types.ResOp4(const.OP_WRITE, const.NFS4_OK, types.Write4Res(4, const.FILE_SYNC4, VERIFIER)),
                types.ResOp4(const.OP_GETATTR, const.NFS4ERR_IO),
                status=const.NFS4ERR_IO,
            )
        )
        client.opened[b"file"] = OpenFile4(b"file", STATEID, const.OPEN4_SHARE_ACCESS_WRITE, const.OPEN4_SHARE_DENY_NONE)

        result = client.write(b"file", 0, 4, b"data", const.FILE_SYNC4)

        self.assertEqual(result["status"], const.NFS4_OK)
        self.assertEqual(result["resok"]["count"], 4)
        self.assertTrue(result["resok"]["file_wcc"]["before"]["present"])
        self.assertFalse(result["resok"]["file_wcc"]["after"]["present"])

    def test_lookup_success_survives_trailing_getattr_failure(self):
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4DIR})
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
                types.ResOp4(const.OP_LOOKUP, const.NFS4_OK),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"file"),
                types.ResOp4(const.OP_GETATTR, const.NFS4ERR_IO),
                status=const.NFS4ERR_IO,
            )
        )

        result = client.lookup(b"directory", b"file")

        self.assertEqual(result["status"], const.NFS4_OK)
        self.assertEqual(result["resok"]["object"]["data"], b"file")
        self.assertTrue(result["resok"]["dir_attributes"]["present"])
        self.assertFalse(result["resok"]["obj_attributes"]["present"])

    def test_create_object_success_survives_trailing_getattr_failure(self):
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4DIR})
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
                types.ResOp4(const.OP_SAVEFH, const.NFS4_OK),
                types.ResOp4(const.OP_CREATE, const.NFS4_OK, types.Create4Res(CHANGE, types.Bitmap4())),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"created"),
                types.ResOp4(const.OP_GETATTR, const.NFS4ERR_IO),
                status=const.NFS4ERR_IO,
            )
        )

        result = client.mkdir(b"parent", b"created")

        self.assertEqual(result["status"], const.NFS4_OK)
        self.assertEqual(result["resok"]["obj"]["handle"]["data"], b"created")
        self.assertFalse(result["resok"]["obj_attributes"]["present"])
        self.assertFalse(result["resok"]["dir_wcc"]["after"]["present"])

    def test_create_object_success_survives_getfh_failure(self):
        attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4DIR})
        client = MockNFSv4(
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_GETATTR, const.NFS4_OK, attributes),
                types.ResOp4(const.OP_SAVEFH, const.NFS4_OK),
                types.ResOp4(const.OP_CREATE, const.NFS4_OK, types.Create4Res(CHANGE, types.Bitmap4())),
                types.ResOp4(const.OP_GETFH, const.NFS4ERR_IO),
                status=const.NFS4ERR_IO,
            )
        )

        result = client.mkdir(b"parent", b"created")

        self.assertEqual(result["status"], const.NFS4_OK)
        self.assertFalse(result["resok"]["obj"]["present"])
        self.assertFalse(result["resok"]["obj_attributes"]["present"])
        self.assertTrue(result["resok"]["dir_wcc"]["before"]["present"])
        self.assertFalse(result["resok"]["dir_wcc"]["after"]["present"])

    def test_exclusive_create_sets_attributes_in_a_separate_compound(self):
        directory_attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4DIR})
        file_attributes = types.Fattr4({const.FATTR4_TYPE: const.NF4REG, const.FATTR4_MODE: 0o600})
        client = MockNFSv4(
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_GETATTR, const.NFS4_OK, directory_attributes)),
            response(types.ResOp4(const.OP_SETCLIENTID, const.NFS4_OK, types.SetClientId4Res(77, VERIFIER))),
            response(types.ResOp4(const.OP_SETCLIENTID_CONFIRM, const.NFS4_OK)),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_OPEN, const.NFS4_OK, types.Open4Res(STATEID, CHANGE, 0, types.Bitmap4())),
                types.ResOp4(const.OP_GETFH, const.NFS4_OK, b"file"),
            ),
            response(
                types.ResOp4(const.OP_PUTFH, const.NFS4_OK),
                types.ResOp4(const.OP_SETATTR, const.NFS4_OK, types.SetAttr4Res(types.Bitmap4.from_bits(const.FATTR4_MODE))),
            ),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_GETATTR, const.NFS4_OK, file_attributes)),
            response(types.ResOp4(const.OP_PUTFH, const.NFS4_OK), types.ResOp4(const.OP_GETATTR, const.NFS4_OK, directory_attributes)),
        )

        self.assertEqual(client.create(b"directory", b"file", EXCLUSIVE, mode=0o600)["status"], const.NFS4_OK)
        self.assertEqual(tuple(operation.op for operation in decode_call(client.calls[3][1]).argarray), (const.OP_PUTFH, const.OP_OPEN, const.OP_GETFH))
        self.assertEqual(tuple(operation.op for operation in decode_call(client.calls[4][1]).argarray), (const.OP_PUTFH, const.OP_SETATTR))
        self.assertEqual(decode_call(client.calls[4][1]).argarray[1].arg.obj_attributes.attributes[const.FATTR4_MODE], 0o600)


if __name__ == "__main__":
    unittest.main()
