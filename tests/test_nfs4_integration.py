import os
import unittest
import uuid

from pyNfsClient import NFSv40, NFSv41, NFSv42
from pyNfsClient import nfs4_const as const
from pyNfsClient import nfs4_types as types
from pyNfsClient import nfs41_const as const41
from pyNfsClient import nfs41_types as types41
from pyNfsClient.nfs4_base import NFS4Error


LIVE = os.getenv("PYNFSCLIENT_NFS4_INTEGRATION") == "1"


class RawNFSv4Integration:
    client_class = None
    minor_version = None

    def auth(self):
        return {
            "flavor": const.AUTH_SYS,
            "machine_name": "pynfsclient-integration",
            "uid": int(os.getenv("PYNFSCLIENT_NFS4_UID", "65534")),
            "gid": int(os.getenv("PYNFSCLIENT_NFS4_GID", "65534")),
            "aux_gid": [],
        }

    def remove(self, client, parent, name, missing_ok=False):
        response = client.compound((client.putfh_op(parent), client.remove_op(name)), tag=b"integration-remove", check=not missing_ok)
        if missing_ok and response.status not in {const.NFS4_OK, const.NFS4ERR_NOENT}:
            raise NFS4Error(response.status, response=response)
        return response

    def delegation_stateid(self, delegation):
        if delegation.delegation_type == const.OPEN_DELEGATE_READ:
            return delegation.read.stateid
        if delegation.delegation_type == const.OPEN_DELEGATE_WRITE:
            return delegation.write.stateid
        return None

    def open_file(self, client, parent, name, owner):
        create_how = types.OpenFlag4(const.OPEN4_CREATE, types.CreateHow4(const.GUARDED4, types.Fattr4({const.FATTR4_MODE: 0o600})))
        if self.minor_version == 0:
            prepared = client.prepare_open(name, const.OPEN4_SHARE_ACCESS_BOTH, const.OPEN4_SHARE_DENY_NONE, create_how)
            response = client.compound((client.putfh_op(parent), prepared, client.getfh_op()), tag=b"integration-open")
            return client.operation_result(response, const.OP_GETFH), prepared.state.stateid, prepared.state
        operation = client.open_op(0, const.OPEN4_SHARE_ACCESS_BOTH | const41.OPEN4_SHARE_ACCESS_WANT_NO_DELEG, const.OPEN4_SHARE_DENY_NONE, types41.OpenOwner4(client.clientid, owner), types41.OpenFlag4(const.OPEN4_CREATE, types41.CreateHow4(const.GUARDED4, types41.Fattr4({const.FATTR4_MODE: 0o600}))), types41.OpenClaim4(const.CLAIM_NULL, file=name))
        response = client.compound((client.putfh_op(parent), operation, client.getfh_op()), tag=b"integration-open")
        result = client.operation_result(response, const.OP_OPEN)
        filehandle = client.operation_result(response, const.OP_GETFH)
        if self.delegation_stateid(result.delegation) is not None:
            client.compound((client.putfh_op(filehandle), client.delegreturn_op(self.delegation_stateid(result.delegation))), tag=b"integration-delegreturn")
        return filehandle, result.stateid, None

    def close_file(self, client, filehandle, stateid, open_state):
        if self.minor_version == 0:
            client.compound((client.putfh_op(filehandle), client.prepare_close(open_state)), tag=b"integration-close")
        else:
            client.compound((client.putfh_op(filehandle), client.close_op(0, stateid)), tag=b"integration-close")

    def cleanup_remote(self, client, state):
        failures = []
        if client.client is None:
            return
        if state["stateid"] is not None and not state["closed"]:
            try:
                self.close_file(client, state["filehandle"], state["stateid"], state["open_state"])
            except Exception as e:
                failures.append(e)
        if state["directory"] is not None:
            for name in (state["file"], state["renamed"]):
                try:
                    self.remove(client, state["directory"], name, missing_ok=True)
                except Exception as e:
                    failures.append(e)
        if state["scratch"] is not None:
            try:
                self.remove(client, state["scratch"], state["directory_name"], missing_ok=True)
            except Exception as e:
                failures.append(e)
        if failures:
            raise failures[0]

    def test_raw_filesystem_workflow(self):
        client = self.client_class(os.getenv("PYNFSCLIENT_NFS4_HOST", "192.168.108.140"), timeout=int(os.getenv("PYNFSCLIENT_NFS4_TIMEOUT", "10")), auth=self.auth())
        state = {
            "scratch": None,
            "directory": None,
            "directory_name": f"integration-{self.minor_version}-{uuid.uuid4().hex}".encode(),
            "file": b"original",
            "renamed": b"renamed",
            "filehandle": None,
            "stateid": None,
            "open_state": None,
            "closed": False,
        }
        client.connect()
        self.addCleanup(client.disconnect)
        self.addCleanup(self.cleanup_remote, client, state)

        response = client.compound((client.putrootfh_op(), client.getfh_op()), tag=b"integration-root")
        root = client.operation_result(response, const.OP_GETFH)
        self.assertTrue(root)

        response = client.compound((client.putfh_op(root), client.lookup_op(b"pynfsclient"), client.getfh_op()), tag=b"integration-lookup")
        state["scratch"] = client.operation_result(response, const.OP_GETFH)
        response = client.compound((client.putfh_op(state["scratch"]), client.getattr_op(types.Bitmap4.from_bits(const.FATTR4_TYPE))), tag=b"integration-getattr")
        self.assertEqual(client.operation_result(response, const.OP_GETATTR).attributes[const.FATTR4_TYPE], const.NF4DIR)

        response = client.compound((client.putfh_op(state["scratch"]), client.create_op(types.CreateType4(const.NF4DIR), state["directory_name"], types.Fattr4({const.FATTR4_MODE: 0o700})), client.getfh_op()), tag=b"integration-mkdir")
        state["directory"] = client.operation_result(response, const.OP_GETFH)
        response = client.compound((client.putfh_op(state["scratch"]), client.readdir_op(attr_request=types.Bitmap4.from_bits(const.FATTR4_TYPE))), tag=b"integration-readdir")
        self.assertIn(state["directory_name"], tuple(entry.name.encode() if isinstance(entry.name, str) else entry.name for entry in client.operation_result(response, const.OP_READDIR).entries))

        state["filehandle"], state["stateid"], state["open_state"] = self.open_file(client, state["directory"], state["file"], state["directory_name"])
        payload = b"raw NFSv4 integration payload"
        response = client.compound((client.putfh_op(state["filehandle"]), client.write_op(state["stateid"], 0, payload)), tag=b"integration-write")
        self.assertEqual(client.operation_result(response, const.OP_WRITE).count, len(payload))
        response = client.compound((client.putfh_op(state["filehandle"]), client.read_op(state["stateid"], 0, len(payload))), tag=b"integration-read")
        self.assertEqual(client.operation_result(response, const.OP_READ).data, payload)

        self.close_file(client, state["filehandle"], state["stateid"], state["open_state"])
        state["closed"] = True
        client.compound((client.putfh_op(state["directory"]), client.savefh_op(), client.putfh_op(state["directory"]), client.rename_op(state["file"], state["renamed"])), tag=b"integration-rename")
        response = client.compound((client.putfh_op(state["directory"]), client.lookup_op(state["renamed"]), client.getfh_op()), tag=b"integration-renamed-lookup")
        self.assertEqual(client.operation_result(response, const.OP_GETFH), state["filehandle"])

        self.remove(client, state["directory"], state["renamed"])
        self.remove(client, state["scratch"], state["directory_name"])
        state["directory"] = None
        client.disconnect()
        self.assertIsNone(client.client)


@unittest.skipUnless(LIVE, "set PYNFSCLIENT_NFS4_INTEGRATION=1 to run NFSv4 integration tests")
class NFSv40IntegrationTests(RawNFSv4Integration, unittest.TestCase):
    client_class = NFSv40
    minor_version = 0

    def test_repeated_open_uses_open_downgrade_before_close(self):
        client = NFSv40(os.getenv("PYNFSCLIENT_NFS4_HOST", "192.168.108.140"), timeout=int(os.getenv("PYNFSCLIENT_NFS4_TIMEOUT", "10")), auth=self.auth())
        name = f"integration-open-{uuid.uuid4().hex}".encode()
        scratch = None
        filehandle = None
        open_states = []
        client.connect()
        self.addCleanup(client.disconnect)
        try:
            response = client.compound((client.putrootfh_op(), client.lookup_op(b"pynfsclient"), client.getfh_op()), tag=b"integration-open-root")
            scratch = client.operation_result(response, const.OP_GETFH)
            create_how = types.OpenFlag4(const.OPEN4_CREATE, types.CreateHow4(const.GUARDED4, types.Fattr4({const.FATTR4_MODE: 0o600})))
            first = client.prepare_open(name, const.OPEN4_SHARE_ACCESS_READ, const.OPEN4_SHARE_DENY_NONE, create_how)
            response = client.compound((client.putfh_op(scratch), first, client.getfh_op()), tag=b"integration-open-first")
            filehandle = client.operation_result(response, const.OP_GETFH)
            open_states.append(first.state)
            second = client.prepare_open(name, const.OPEN4_SHARE_ACCESS_WRITE)
            client.compound((client.putfh_op(scratch), second, client.getfh_op()), tag=b"integration-open-second")
            open_states.append(second.state)
            self.assertIsNot(first.state, second.state)
            self.assertIs(first.state.state, second.state.state)

            downgrade = client.prepare_close(first.state)
            self.assertEqual(downgrade.operation.op, const.OP_OPEN_DOWNGRADE)
            client.compound((client.putfh_op(filehandle), downgrade), tag=b"integration-open-downgrade")
            self.assertEqual(second.state.share_access, const.OPEN4_SHARE_ACCESS_WRITE)
            client.compound((client.putfh_op(filehandle), client.prepare_close(second.state)), tag=b"integration-open-close")
            open_states.clear()
            self.remove(client, scratch, name)
            filehandle = None
        finally:
            for open_state in open_states:
                if not open_state.closed:
                    try:
                        client.compound((client.putfh_op(filehandle), client.prepare_close(open_state)), tag=b"integration-open-cleanup")
                    except Exception:
                        break
            if scratch is not None and filehandle is not None:
                self.remove(client, scratch, name, missing_ok=True)


@unittest.skipUnless(LIVE, "set PYNFSCLIENT_NFS4_INTEGRATION=1 to run NFSv4 integration tests")
class NFSv41IntegrationTests(RawNFSv4Integration, unittest.TestCase):
    client_class = NFSv41
    minor_version = 1


@unittest.skipUnless(LIVE, "set PYNFSCLIENT_NFS4_INTEGRATION=1 to run NFSv4 integration tests")
class NFSv42IntegrationTests(RawNFSv4Integration, unittest.TestCase):
    client_class = NFSv42
    minor_version = 2


if __name__ == "__main__":
    unittest.main()
