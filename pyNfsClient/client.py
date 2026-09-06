import secrets
from dataclasses import dataclass, field

from . import const as v3
from . import nfs4_const as const
from . import nfs4_types as types
from . import nfs41_const as const41
from . import nfs41_types as types41
from . import nfs42_const as const42
from .mount import Mount
from .nfs3 import NFSv3, fh_check
from .nfs40 import NFSv40
from .nfs41 import NFSv41
from .nfs42 import NFSv42
from .nfs4_base import DEFAULT_ATTRIBUTES, DIRECTORY_ATTRIBUTES, NFS4Error
from .portmap import Portmap
from .utils import str_to_bytes


VERSIONS = ("3", "4.0", "4.1", "4.2")
READDIR_ATTRIBUTES = types.Bitmap4.from_bits(const.FATTR4_FILEID)
FILESYSTEM_ATTRIBUTES = types.Bitmap4.from_bits(
    *DEFAULT_ATTRIBUTES.bits(), const.FATTR4_FILES_AVAIL, const.FATTR4_FILES_FREE,
    const.FATTR4_FILES_TOTAL, const.FATTR4_SPACE_AVAIL, const.FATTR4_SPACE_FREE,
    const.FATTR4_SPACE_TOTAL,
)
FSINFO_ATTRIBUTES = types.Bitmap4.from_bits(
    *DEFAULT_ATTRIBUTES.bits(), const.FATTR4_CANSETTIME, const.FATTR4_HOMOGENEOUS,
    const.FATTR4_LINK_SUPPORT, const.FATTR4_SYMLINK_SUPPORT, const.FATTR4_MAXFILESIZE,
    const.FATTR4_MAXREAD, const.FATTR4_MAXWRITE, const.FATTR4_TIME_DELTA,
)
PATHCONF_ATTRIBUTES = types.Bitmap4.from_bits(
    *DEFAULT_ATTRIBUTES.bits(), const.FATTR4_MAXLINK, const.FATTR4_MAXNAME,
    const.FATTR4_NO_TRUNC, const.FATTR4_CHOWN_RESTRICTED, const.FATTR4_CASE_INSENSITIVE,
    const.FATTR4_CASE_PRESERVING,
)


@dataclass(slots=True)
class OpenFile:
    filehandle: bytes
    stateid: types.Stateid4
    share_access: int
    share_deny: int
    principal: object
    auth: object
    references: list = field(default_factory=list)


def nfs3_identity(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return int(value) if isinstance(value, str) and value.isdecimal() else value


def nfs3_time(value=None):
    return {"seconds": 0 if value is None else value.seconds, "nseconds": 0 if value is None else value.nseconds}


def nfs3_attributes(attributes):
    values = attributes.attributes
    rawdev = values.get(const.FATTR4_RAWDEV, types.SpecData4(0, 0))
    fsid = values.get(const.FATTR4_FSID, types.Fsid4(0, 0))
    return {
        "type": values.get(const.FATTR4_TYPE, const.NF4REG),
        "mode": values.get(const.FATTR4_MODE, 0),
        "nlink": values.get(const.FATTR4_NUMLINKS, 1),
        "uid": nfs3_identity(values.get(const.FATTR4_OWNER, 0)),
        "gid": nfs3_identity(values.get(const.FATTR4_OWNER_GROUP, 0)),
        "size": values.get(const.FATTR4_SIZE, 0),
        "used": values.get(const.FATTR4_SPACE_USED, values.get(const.FATTR4_SIZE, 0)),
        "rdev": {"major": rawdev.specdata1, "minor": rawdev.specdata2},
        "fsid": fsid.major << 64 | fsid.minor,
        "fileid": values.get(const.FATTR4_FILEID, 0),
        "atime": nfs3_time(values.get(const.FATTR4_TIME_ACCESS)),
        "mtime": nfs3_time(values.get(const.FATTR4_TIME_MODIFY)),
        "ctime": nfs3_time(values.get(const.FATTR4_TIME_METADATA)),
    }


def post_op_attributes(attributes=None):
    if attributes is not None and attributes.attributes.get(const.FATTR4_RDATTR_ERROR, const.NFS4_OK) != const.NFS4_OK:
        attributes = None
    return {"present": attributes is not None, "attributes": None if attributes is None else nfs3_attributes(attributes)}


def post_op_handle(filehandle=None):
    return {"present": filehandle is not None, "handle": None if filehandle is None else {"data": filehandle}}


def wcc_data(attributes=None, before=None):
    return {
        "before": {
            "present": before is not None,
            "attributes": None if before is None else {"size": nfs3_attributes(before)["size"], "mtime": nfs3_attributes(before)["mtime"], "ctime": nfs3_attributes(before)["ctime"]},
        },
        "after": post_op_attributes(attributes),
    }


def response_failure(status, failure):
    return {"status": status, "resok": None, "resfail": failure}


def wcc_failure(status, failure):
    return {"status": status, "resfail": failure}


def operation_results(response, operation):
    return tuple(result.result for result in response.resarray if result.op == operation and result.status == const.NFS4_OK)


def operation_status(response, operation, occurrence=0):
    for result in response.resarray:
        if result.op == operation:
            if occurrence == 0:
                return result.status
            occurrence -= 1
    return response.status


def verifier8(value):
    return str_to_bytes(value).ljust(const.NFS4_VERIFIER_SIZE, b"\0")[:const.NFS4_VERIFIER_SIZE]


def nfs4_settime(flag, seconds, nseconds):
    if flag == v3.DONT_CHANGE:
        return None
    if flag == v3.SET_TO_SERVER_TIME:
        return types.SetTime4(const.SET_TO_SERVER_TIME4)
    if flag == v3.SET_TO_CLIENT_TIME:
        return types.SetTime4(const.SET_TO_CLIENT_TIME4, types.NfsTime4(0 if seconds is None else seconds, 0 if nseconds is None else nseconds))
    raise ValueError(f"time flag must be one of {tuple(v3.time_how)}")


def nfs4_attributes(mode=None, uid=None, gid=None, size=None, atime_flag=v3.SET_TO_SERVER_TIME, atime_s=None, atime_ns=None, mtime_flag=v3.SET_TO_SERVER_TIME, mtime_s=None, mtime_ns=None):
    attributes = {}
    if mode is not None:
        attributes[const.FATTR4_MODE] = int(mode)
    if uid is not None:
        attributes[const.FATTR4_OWNER] = str(uid)
    if gid is not None:
        attributes[const.FATTR4_OWNER_GROUP] = str(gid)
    if size is not None:
        attributes[const.FATTR4_SIZE] = int(size)
    if nfs4_settime(atime_flag, atime_s, atime_ns) is not None:
        attributes[const.FATTR4_TIME_ACCESS_SET] = nfs4_settime(atime_flag, atime_s, atime_ns)
    if nfs4_settime(mtime_flag, mtime_s, mtime_ns) is not None:
        attributes[const.FATTR4_TIME_MODIFY_SET] = nfs4_settime(mtime_flag, mtime_s, mtime_ns)
    return types.Fattr4(attributes)


def linked_entries(entries, include_attributes):
    linked = []
    for entry in reversed(entries):
        values = entry.attrs.attributes
        item = {"fileid": values.get(const.FATTR4_FILEID, 0), "name": str_to_bytes(entry.name), "cookie": entry.cookie, "nextentry": linked}
        if include_attributes:
            item["name_attributes"] = post_op_attributes(entry.attrs)
            item["name_handle"] = post_op_handle(values.get(const.FATTR4_FILEHANDLE))
        linked = [item]
    return linked


class NFSClient:
    def __init__(self, host, version="3", port=None, timeout=5, auth=None, *, client_identity=None):
        if version not in VERSIONS:
            raise ValueError(f"NFS version must be one of {', '.join(VERSIONS)}")
        if version == "3" and client_identity is not None:
            raise ValueError("client_identity only applies to NFSv4")
        self.host = host
        self.version = version
        self.requested_port = port
        self.port = port
        self.timeout = timeout
        self.auth = auth
        self.mount_auth = auth
        self.client_identity = client_identity
        self.raw = None
        self.portmap = None
        self.mount = None
        self.gss_auth = None
        self.locations = {}
        self.opened = {}
        self.open_owners = {}
        if version != "3":
            self.port = 2049 if port is None else port
            self.raw = {"4.0": NFSv40, "4.1": NFSv41, "4.2": NFSv42}[version](host, self.port, timeout, auth, client_identity=client_identity)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.disconnect()

    def connect(self):
        if self.raw is not None and self.raw.client is not None:
            return self
        try:
            if self.version == "3":
                self.portmap = Portmap(self.host, timeout=self.timeout, port=v3.PORTMAP_PORT)
                self.portmap.connect()
                self.port = self.portmap.getport(v3.NFS_PROGRAM, v3.NFS_V3) if self.requested_port is None else self.requested_port
                self.raw = NFSv3(self.host, self.port, self.timeout, self.auth)
                self.mount = Mount(self.host, self.portmap.getport(Mount.program, Mount.program_version), self.timeout, self.mount_auth)
                self.raw.connect()
                self.mount.connect()
            else:
                self.raw.connect()
        except Exception as e:
            for rpc in (self.mount, self.raw, self.portmap):
                if rpc is not None:
                    try:
                        rpc.disconnect()
                    except Exception as e:
                        pass
            if self.version == "3":
                self.raw = None
                self.mount = None
                self.portmap = None
                self.port = self.requested_port
            raise
        return self

    def set_auth(self, auth):
        self.auth = auth
        if self.raw is not None:
            self.raw.auth = auth
        return auth

    def establish_gss(self, initiator, service="krb5i"):
        if self.raw is None or self.raw.client is None:
            raise RuntimeError("connect the NFS client before establishing RPCSEC_GSS")
        from .rpcsec_gss import RPCSECGSSAuth

        self.gss_auth = RPCSECGSSAuth.establish(self.raw, v3.NFS_PROGRAM, v3.NFS_V3 if self.version == "3" else const.NFS_V4, initiator, service)
        return self.set_auth(self.gss_auth)

    def disconnect(self):
        failure = None
        for opened in tuple(self.opened.values()):
            try:
                status = self.close_opened(opened)
                if status != const.NFS4_OK:
                    failure = failure or NFS4Error(status)
            except Exception as e:
                failure = failure or e
        if self.version in ("4.1", "4.2") and self.raw is not None:
            try:
                self.raw.destroy_session()
            except Exception as e:
                failure = failure or e
            try:
                self.raw.destroy_client()
            except Exception as e:
                failure = failure or e
        if self.gss_auth is not None and self.raw is not None and self.raw.client is not None:
            try:
                self.gss_auth.destroy(self.raw, v3.NFS_PROGRAM, v3.NFS_V3 if self.version == "3" else const.NFS_V4)
            except Exception as e:
                failure = failure or e
        for rpc in (self.raw, self.mount, self.portmap):
            if rpc is not None:
                try:
                    rpc.disconnect()
                except Exception as e:
                    failure = failure or e
        self.opened.clear()
        self.open_owners.clear()
        self.locations.clear()
        self.gss_auth = None
        if failure is not None:
            raise failure

    def effective_auth(self, auth):
        return self.auth if auth is None else auth

    def auth_snapshot(self, auth):
        auth = self.effective_auth(auth)
        return self.raw.auth_snapshot(auth) if self.version != "3" else dict(auth) if isinstance(auth, dict) else auth

    def principal(self, auth):
        return self.raw.auth_identity(self.effective_auth(auth))

    def state_key(self, filehandle, auth, share_access=0, share_deny=0):
        return self.version, getattr(self.raw, "clientid", None), self.principal(auth), filehandle, share_access, share_deny

    def find_open(self, filehandle, auth, share_access=0, share_deny=0):
        identity = self.version, getattr(self.raw, "clientid", None), self.principal(auth), filehandle
        for key, opened in self.opened.items():
            if key[:4] == identity and opened.share_access & share_access == share_access and opened.share_deny & share_deny == share_deny:
                return key, opened
        return None, None

    def status_name(self, status):
        return v3.NFSSTAT3.get(status, f"NFSv3 status {status}") if self.version == "3" else const42.NFSSTAT4.get(status, f"NFSv4 status {status}")

    def root_handle(self, path="/", auth=None):
        if self.version == "3":
            return self.mount.mnt(path, auth=auth)
        response = self.raw.compound((self.raw.putrootfh_op(), self.raw.getfh_op()), tag=b"client-root", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return {"status": response.status}
        filehandle = self.raw.operation_result(response, const.OP_GETFH)
        for component in filter(None, path.replace("\\", "/").split("/")):
            found = self.lookup(filehandle, component, auth=auth)
            if found["status"] != const.NFS4_OK:
                return {"status": found["status"]}
            filehandle = found["resok"]["object"]["data"]
        return {"status": const.NFS4_OK, "mountinfo": {"fhandle": filehandle}}

    def export_groups(self, groups):
        result = []
        for group in groups:
            result.append(group.gr_name.decode(errors="replace"))
            if group.gr_next:
                result.extend(self.export_groups(group.gr_next))
        return result

    def export_nodes(self, nodes):
        result = []
        for node in nodes:
            result.append((node.ex_dir.decode(errors="replace"), self.export_groups(node.ex_groups) or ["Everyone"]))
            if node.ex_next:
                result.extend(self.export_nodes(node.ex_next))
        return result

    def exports(self):
        return self.export_nodes(self.mount.export()) if self.version == "3" else [("/", ["Everyone"])]

    def unmount(self, auth=None):
        return self.mount.umnt(auth=auth) if self.version == "3" else {"status": v3.MNT3_OK, "message": v3.MOUNTSTAT3[v3.MNT3_OK]}

    def null(self):
        if self.version == "3":
            return self.raw.null()
        self.raw.null()
        return {"status": const.NFS4_OK, "resok": None}

    def with_filehandle(self, filehandle, *operations, tag=b"", auth=None, check=True):
        return self.raw.compound((self.raw.putfh_op(filehandle), *operations), tag=tag, auth=auth, check=check)

    def with_filehandles(self, current_filehandle, saved_filehandle, *operations, tag=b"", auth=None, check=True):
        return self.raw.compound((self.raw.putfh_op(saved_filehandle), self.raw.savefh_op(), self.raw.putfh_op(current_filehandle), *operations), tag=tag, auth=auth, check=check)

    def supported_attributes(self, filehandle, requested, auth=None):
        response = self.with_filehandle(filehandle, self.raw.getattr_op(types.Bitmap4.from_bits(const.FATTR4_SUPPORTED_ATTRS)), tag=b"supported-attributes", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response.status, types.Bitmap4()
        supported = self.raw.operation_result(response, const.OP_GETATTR).attributes[const.FATTR4_SUPPORTED_ATTRS]
        return const.NFS4_OK, types.Bitmap4.from_bits(*(set(requested.bits()) & set(supported.bits())))

    def get_attributes4(self, filehandle, requested=DEFAULT_ATTRIBUTES, auth=None):
        status, attributes = self.supported_attributes(filehandle, requested, auth)
        if status != const.NFS4_OK:
            return status, None
        response = self.with_filehandle(filehandle, self.raw.getattr_op(attributes), tag=b"getattr", auth=auth, check=False)
        return response.status, operation_results(response, const.OP_GETATTR)[0] if operation_results(response, const.OP_GETATTR) else None

    def open_owner(self, auth):
        principal = self.principal(auth)
        if principal not in self.open_owners:
            self.open_owners[principal] = b"pyNfsClient:" + secrets.token_bytes(12)
        return types.OpenOwner4(self.raw.clientid, self.open_owners[principal])

    def delegation_stateid(self, delegation):
        if delegation.delegation_type == const.OPEN_DELEGATE_READ:
            return delegation.read.stateid
        if delegation.delegation_type == const.OPEN_DELEGATE_WRITE:
            return delegation.write.stateid
        raise ValueError("OPEN result does not contain a delegation")

    def return_delegation(self, filehandle, result, auth):
        if result.delegation.delegation_type in (const.OPEN_DELEGATE_READ, const.OPEN_DELEGATE_WRITE):
            self.with_filehandle(filehandle, self.raw.delegreturn_op(self.delegation_stateid(result.delegation)), tag=b"delegreturn", auth=auth)

    def open_existing(self, filehandle, share_access, auth=None):
        auth = self.auth_snapshot(auth)
        key, opened = self.find_open(filehandle, auth, share_access)
        if opened is not None:
            return opened
        old_key, opened = self.find_open(filehandle, auth)
        share_access |= 0 if opened is None else opened.share_access
        if self.version == "4.0":
            if filehandle not in self.locations:
                return OpenFile(filehandle, types.Stateid4(), share_access, const.OPEN4_SHARE_DENY_NONE, self.principal(auth), auth)
            parent, name = self.locations[filehandle]
            prepared = self.raw.prepare_open(name, share_access, const.OPEN4_SHARE_DENY_NONE, auth=auth)
            response = self.raw.compound((self.raw.putfh_op(parent), prepared, self.raw.getfh_op()), tag=b"open", auth=auth, check=False)
            if response.status != const.NFS4_OK:
                raise NFS4Error(response.status, response=response)
            reopened = self.raw.operation_result(response, const.OP_GETFH)
            if reopened != filehandle:
                if prepared.state is not None:
                    self.raw.compound((self.raw.putfh_op(reopened), self.raw.prepare_close(prepared.state, auth)), tag=b"close-replacement", auth=auth, check=False)
                self.locations.pop(filehandle, None)
                return OpenFile(filehandle, types.Stateid4(), share_access, const.OPEN4_SHARE_DENY_NONE, self.principal(auth), auth)
            references = ([] if opened is None else opened.references) + [prepared.state]
            opened = OpenFile(filehandle, prepared.state.stateid, share_access, const.OPEN4_SHARE_DENY_NONE, self.principal(auth), auth, references)
        else:
            self.raw.ensure_session(auth)
            response = self.raw.compound((self.raw.putfh_op(filehandle), self.raw.open_op(0, share_access | const41.OPEN4_SHARE_ACCESS_WANT_NO_DELEG, const.OPEN4_SHARE_DENY_NONE, self.open_owner(auth), types.OpenFlag4(), types41.OpenClaim4(const41.CLAIM_FH)), self.raw.getfh_op()), tag=b"open", auth=auth, check=False)
            if response.status != const.NFS4_OK:
                raise NFS4Error(response.status, response=response)
            result = self.raw.operation_result(response, const.OP_OPEN)
            if self.raw.operation_result(response, const.OP_GETFH) != filehandle:
                raise NFS4Error(const.NFS4ERR_BADHANDLE, response=response)
            opened = OpenFile(filehandle, result.stateid, share_access, const.OPEN4_SHARE_DENY_NONE, self.principal(auth), auth)
        if old_key is not None:
            self.opened.pop(old_key)
        self.opened[self.state_key(filehandle, auth, opened.share_access, opened.share_deny)] = opened
        if self.version != "4.0":
            self.return_delegation(filehandle, result, auth)
        return opened

    def open_create(self, dir_handle, name, create_mode, attributes, verf, auth=None):
        auth = self.auth_snapshot(auth)
        if self.version == "4.0":
            openhow = types.OpenFlag4(const.OPEN4_CREATE, types.CreateHow4(create_mode, createattrs=attributes if create_mode != v3.EXCLUSIVE else None, createverf=verifier8(verf) if create_mode == v3.EXCLUSIVE else None))
            prepared = self.raw.prepare_open(str_to_bytes(name), const.OPEN4_SHARE_ACCESS_BOTH, const.OPEN4_SHARE_DENY_NONE, openhow, auth=auth)
            response = self.raw.compound((self.raw.putfh_op(dir_handle), prepared, self.raw.getfh_op()), tag=b"create", auth=auth, check=False)
            if response.status != const.NFS4_OK:
                raise NFS4Error(response.status, response=response)
            filehandle = self.raw.operation_result(response, const.OP_GETFH)
            opened = OpenFile(filehandle, prepared.state.stateid, const.OPEN4_SHARE_ACCESS_BOTH, const.OPEN4_SHARE_DENY_NONE, self.principal(auth), auth, [prepared.state])
        else:
            self.raw.ensure_session(auth)
            openhow = types.OpenFlag4(const.OPEN4_CREATE, types.CreateHow4(create_mode, createattrs=attributes if create_mode != v3.EXCLUSIVE else None, createverf=verifier8(verf) if create_mode == v3.EXCLUSIVE else None))
            response = self.raw.compound((self.raw.putfh_op(dir_handle), self.raw.open_op(0, const.OPEN4_SHARE_ACCESS_BOTH | const41.OPEN4_SHARE_ACCESS_WANT_NO_DELEG, const.OPEN4_SHARE_DENY_NONE, self.open_owner(auth), openhow, types41.OpenClaim4(const.CLAIM_NULL, file=str_to_bytes(name))), self.raw.getfh_op()), tag=b"create", auth=auth, check=False)
            if response.status != const.NFS4_OK:
                raise NFS4Error(response.status, response=response)
            result = self.raw.operation_result(response, const.OP_OPEN)
            filehandle = self.raw.operation_result(response, const.OP_GETFH)
            opened = OpenFile(filehandle, result.stateid, const.OPEN4_SHARE_ACCESS_BOTH, const.OPEN4_SHARE_DENY_NONE, self.principal(auth), auth)
        self.locations[filehandle] = (dir_handle, str_to_bytes(name))
        self.opened[self.state_key(filehandle, auth, opened.share_access, opened.share_deny)] = opened
        if self.version != "4.0":
            self.return_delegation(filehandle, result, auth)
        return opened

    def open_stateid(self, opened):
        return opened.references[-1].stateid if opened.references else opened.stateid

    def close_opened(self, opened):
        if self.version == "4.0":
            for reference in reversed(opened.references):
                if reference.closed:
                    continue
                response = self.raw.compound((self.raw.putfh_op(opened.filehandle), self.raw.prepare_close(reference, opened.auth)), tag=b"close", auth=opened.auth, check=False)
                if response.status != const.NFS4_OK:
                    return response.status
            return const.NFS4_OK
        response = self.raw.compound((self.raw.putfh_op(opened.filehandle), self.raw.close_op(0, opened.stateid)), tag=b"close", auth=opened.auth, check=False)
        return response.status

    def close(self, file_handle, auth=None):
        if self.version == "3":
            return {"status": v3.NFS3_OK, "resok": None}
        key, opened = self.find_open(file_handle, auth)
        if opened is None:
            return {"status": const.NFS4_OK, "resok": None}
        status = self.close_opened(opened)
        if status == const.NFS4_OK:
            self.opened.pop(key)
        return {"status": status, "resok": None if status == const.NFS4_OK else None}

    @fh_check
    def getattr(self, file_handle, auth=None):
        if self.version == "3":
            return self.raw.getattr(file_handle, auth=auth)
        status, attributes = self.get_attributes4(file_handle, auth=auth)
        return {"status": status, "attributes": None if attributes is None else nfs3_attributes(attributes)}

    @fh_check
    def setattr(self, file_handle, mode=None, uid=None, gid=None, size=None, atime_flag=v3.SET_TO_SERVER_TIME, atime_s=None, atime_us=None, mtime_flag=v3.SET_TO_SERVER_TIME, mtime_s=None, mtime_us=None, check=False, obj_ctime=None, auth=None):
        if self.version == "3":
            return self.raw.setattr(file_handle, mode, uid, gid, size, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us, check, obj_ctime, auth)
        status, before = self.get_attributes4(file_handle, auth=auth)
        operations = []
        if check:
            seconds = obj_ctime["seconds"] if isinstance(obj_ctime, dict) else obj_ctime.seconds
            nseconds = obj_ctime["nseconds"] if isinstance(obj_ctime, dict) else obj_ctime.nseconds
            operations.append(self.raw.verify_op(types.Fattr4({const.FATTR4_TIME_METADATA: types.NfsTime4(seconds, nseconds)})))
        try:
            stateid = self.open_stateid(self.open_existing(file_handle, const.OPEN4_SHARE_ACCESS_WRITE, auth)) if size is not None else types.Stateid4()
        except NFS4Error as e:
            return wcc_failure(e.status, wcc_data(before=before if status == const.NFS4_OK else None))
        operations.append(self.raw.setattr_op(stateid, nfs4_attributes(mode, uid, gid, size, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us)))
        response = self.with_filehandle(file_handle, *operations, tag=b"setattr", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return wcc_failure(response.status, wcc_data(before=before if status == const.NFS4_OK else None))
        after_status, after = self.get_attributes4(file_handle, auth=auth)
        return {"status": const.NFS4_OK, "resok": wcc_data(after if after_status == const.NFS4_OK else None, before if status == const.NFS4_OK else None)}

    @fh_check
    def lookup(self, dir_handle, file_folder, auth=None):
        if self.version == "3":
            return self.raw.lookup(dir_handle, file_folder, auth=auth)
        parent_status, parent = self.get_attributes4(dir_handle, auth=auth)
        status, attributes = self.supported_attributes(dir_handle, DEFAULT_ATTRIBUTES, auth)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes(parent if parent_status == const.NFS4_OK else None))
        response = self.with_filehandle(dir_handle, self.raw.lookup_op(str_to_bytes(file_folder)), self.raw.getfh_op(), self.raw.getattr_op(attributes), tag=b"lookup", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes(parent if parent_status == const.NFS4_OK else None))
        filehandle = self.raw.operation_result(response, const.OP_GETFH)
        self.locations[filehandle] = (dir_handle, str_to_bytes(file_folder))
        return {"status": const.NFS4_OK, "resok": {"object": {"data": filehandle}, "obj_attributes": post_op_attributes(self.raw.operation_result(response, const.OP_GETATTR)), "dir_attributes": post_op_attributes(parent if parent_status == const.NFS4_OK else None)}}

    @fh_check
    def access(self, file_handle, access_option, auth=None):
        if self.version == "3":
            return self.raw.access(file_handle, access_option, auth=auth)
        status, attributes = self.get_attributes4(file_handle, auth=auth)
        response = self.with_filehandle(file_handle, self.raw.access_op(access_option), tag=b"access", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes(attributes if status == const.NFS4_OK else None))
        return {"status": const.NFS4_OK, "resok": {"obj_attributes": post_op_attributes(attributes if status == const.NFS4_OK else None), "access": self.raw.operation_result(response, const.OP_ACCESS).access}}

    @fh_check
    def readlink(self, file_handle, auth=None):
        if self.version == "3":
            return self.raw.readlink(file_handle, auth=auth)
        status, attributes = self.get_attributes4(file_handle, auth=auth)
        response = self.with_filehandle(file_handle, self.raw.readlink_op(), tag=b"readlink", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes(attributes if status == const.NFS4_OK else None))
        return {"status": const.NFS4_OK, "resok": {"symlink_attributes": post_op_attributes(attributes if status == const.NFS4_OK else None), "data": self.raw.operation_result(response, const.OP_READLINK)}}

    @fh_check
    def read(self, file_handle, offset=0, chunk_count=1024 * 1024, auth=None):
        if self.version == "3":
            return self.raw.read(file_handle, offset, chunk_count, auth)
        try:
            opened = self.open_existing(file_handle, const.OPEN4_SHARE_ACCESS_READ, auth)
        except NFS4Error as e:
            return response_failure(e.status, post_op_attributes())
        limits = self.fsinfo(file_handle, auth)
        if limits["status"] != const.NFS4_OK:
            return limits
        response = self.with_filehandle(file_handle, self.raw.read_op(self.open_stateid(opened), offset, min(chunk_count, limits["resok"]["rtpref"])), tag=b"read", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes())
        result = self.raw.operation_result(response, const.OP_READ)
        status, attributes = self.get_attributes4(file_handle, auth=auth)
        return {"status": const.NFS4_OK, "resok": {"file_attributes": post_op_attributes(attributes if status == const.NFS4_OK else None), "count": len(result.data), "eof": result.eof, "data": result.data}}

    @fh_check
    def write(self, file_handle, offset, count, content, stable_how, auth=None):
        if self.version == "3":
            return self.raw.write(file_handle, offset, count, content, stable_how, auth)
        content = str_to_bytes(content)
        if count != len(content):
            return response_failure(const.NFS4ERR_INVAL, wcc_data())
        try:
            opened = self.open_existing(file_handle, const.OPEN4_SHARE_ACCESS_WRITE, auth)
        except NFS4Error as e:
            return response_failure(e.status, wcc_data())
        before_status, before = self.get_attributes4(file_handle, auth=auth)
        response = self.with_filehandle(file_handle, self.raw.write_op(self.open_stateid(opened), offset, content, stable_how), tag=b"write", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, wcc_data(before=before if before_status == const.NFS4_OK else None))
        result = self.raw.operation_result(response, const.OP_WRITE)
        after_status, after = self.get_attributes4(file_handle, auth=auth)
        return {"status": const.NFS4_OK, "resok": {"file_wcc": wcc_data(after if after_status == const.NFS4_OK else None, before if before_status == const.NFS4_OK else None), "count": result.count, "committed": result.committed, "verf": result.writeverf}}

    @fh_check
    def create(self, dir_handle, file_name, create_mode, mode=None, uid=None, gid=None, size=None, atime_flag=v3.SET_TO_SERVER_TIME, atime_s=None, atime_us=None, mtime_flag=v3.SET_TO_SERVER_TIME, mtime_s=None, mtime_us=None, verf="0", auth=None):
        if self.version == "3":
            return self.raw.create(dir_handle, file_name, create_mode, mode, uid, gid, size, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us, verf, auth)
        if create_mode not in (v3.UNCHECKED, v3.GUARDED, v3.EXCLUSIVE):
            raise ValueError("create_mode must be UNCHECKED, GUARDED, or EXCLUSIVE")
        before_status, before = self.get_attributes4(dir_handle, auth=auth)
        attributes = nfs4_attributes(mode, uid, gid, size, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us)
        try:
            opened = self.open_create(dir_handle, file_name, create_mode, attributes, verf, auth)
        except NFS4Error as e:
            return response_failure(e.status, wcc_data(before=before if before_status == const.NFS4_OK else None))
        if create_mode == v3.EXCLUSIVE and attributes.attributes:
            response = self.with_filehandle(opened.filehandle, self.raw.setattr_op(self.open_stateid(opened), attributes), tag=b"exclusive-create-setattr", auth=auth, check=False)
            if response.status != const.NFS4_OK:
                return response_failure(response.status, wcc_data(before=before if before_status == const.NFS4_OK else None))
        object_status, object_attributes = self.get_attributes4(opened.filehandle, auth=auth)
        after_status, after = self.get_attributes4(dir_handle, auth=auth)
        return {"status": const.NFS4_OK, "resok": {"obj": post_op_handle(opened.filehandle), "obj_attributes": post_op_attributes(object_attributes if object_status == const.NFS4_OK else None), "dir_wcc": wcc_data(after if after_status == const.NFS4_OK else None, before if before_status == const.NFS4_OK else None)}}

    def create_object(self, dir_handle, name, objtype, attributes, auth=None):
        before_status, before = self.get_attributes4(dir_handle, auth=auth)
        response = self.with_filehandle(dir_handle, self.raw.create_op(objtype, str_to_bytes(name), attributes), self.raw.getfh_op(), tag=b"create-object", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, wcc_data(before=before if before_status == const.NFS4_OK else None))
        filehandle = self.raw.operation_result(response, const.OP_GETFH)
        self.locations[filehandle] = (dir_handle, str_to_bytes(name))
        object_status, object_attributes = self.get_attributes4(filehandle, auth=auth)
        after_status, after = self.get_attributes4(dir_handle, auth=auth)
        return {"status": const.NFS4_OK, "resok": {"obj": post_op_handle(filehandle), "obj_attributes": post_op_attributes(object_attributes if object_status == const.NFS4_OK else None), "dir_wcc": wcc_data(after if after_status == const.NFS4_OK else None, before if before_status == const.NFS4_OK else None)}}

    @fh_check
    def mkdir(self, dir_handle, dir_name, mode=None, uid=None, gid=None, atime_flag=v3.SET_TO_SERVER_TIME, atime_s=None, atime_us=None, mtime_flag=v3.SET_TO_SERVER_TIME, mtime_s=None, mtime_us=None, auth=None):
        if self.version == "3":
            return self.raw.mkdir(dir_handle, dir_name, mode, uid, gid, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us, auth)
        return self.create_object(dir_handle, dir_name, types.CreateType4(const.NF4DIR), nfs4_attributes(mode, uid, gid, None, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us), auth)

    @fh_check
    def symlink(self, dir_handle, link_name, link_to_path, auth=None):
        if self.version == "3":
            return self.raw.symlink(dir_handle, link_name, link_to_path, auth)
        return self.create_object(dir_handle, link_name, types.CreateType4(const.NF4LNK, linkdata=str_to_bytes(link_to_path)), types.Fattr4(), auth)

    @fh_check
    def mknod(self, dir_handle, file_name, ftype, mode=None, uid=None, gid=None, atime_flag=v3.SET_TO_SERVER_TIME, atime_s=None, atime_us=None, mtime_flag=v3.SET_TO_SERVER_TIME, mtime_s=None, mtime_us=None, spec_major=0, spec_minor=0, auth=None):
        if self.version == "3":
            return self.raw.mknod(dir_handle, file_name, ftype, mode, uid, gid, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us, spec_major, spec_minor, auth)
        if ftype not in (v3.NF3CHR, v3.NF3BLK, v3.NF3SOCK, v3.NF3FIFO):
            raise ValueError("ftype must be NF3CHR, NF3BLK, NF3SOCK, or NF3FIFO")
        objtype = types.CreateType4(ftype, devdata=types.SpecData4(spec_major, spec_minor) if ftype in (v3.NF3CHR, v3.NF3BLK) else None)
        return self.create_object(dir_handle, file_name, objtype, nfs4_attributes(mode, uid, gid, None, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us), auth)

    def remove_name(self, dir_handle, name, auth=None):
        before_status, before = self.get_attributes4(dir_handle, auth=auth)
        for filehandle, location in tuple(self.locations.items()):
            if location == (dir_handle, str_to_bytes(name)):
                self.close(filehandle, auth)
        response = self.with_filehandle(dir_handle, self.raw.remove_op(str_to_bytes(name)), tag=b"remove", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return wcc_failure(response.status, wcc_data(before=before if before_status == const.NFS4_OK else None))
        for filehandle, location in tuple(self.locations.items()):
            if location == (dir_handle, str_to_bytes(name)):
                self.locations.pop(filehandle, None)
        after_status, after = self.get_attributes4(dir_handle, auth=auth)
        return {"status": const.NFS4_OK, "resok": wcc_data(after if after_status == const.NFS4_OK else None, before if before_status == const.NFS4_OK else None)}

    @fh_check
    def remove(self, dir_handle, file_name, auth=None):
        return self.raw.remove(dir_handle, file_name, auth) if self.version == "3" else self.remove_name(dir_handle, file_name, auth)

    @fh_check
    def rmdir(self, dir_handle, dir_name, auth=None):
        return self.raw.rmdir(dir_handle, dir_name, auth) if self.version == "3" else self.remove_name(dir_handle, dir_name, auth)

    @fh_check
    def rename(self, dir_handle_from, from_name, dir_handle_to, to_name, auth=None):
        if self.version == "3":
            return self.raw.rename(dir_handle_from, from_name, dir_handle_to, to_name, auth)
        if not isinstance(dir_handle_to, bytes):
            raise TypeError("file handle should be bytes")
        from_status, from_before = self.get_attributes4(dir_handle_from, auth=auth)
        to_status, to_before = self.get_attributes4(dir_handle_to, auth=auth)
        response = self.with_filehandles(dir_handle_to, dir_handle_from, self.raw.rename_op(str_to_bytes(from_name), str_to_bytes(to_name)), tag=b"rename", auth=auth, check=False)
        if response.status == const.NFS4_OK:
            for filehandle, location in tuple(self.locations.items()):
                if location == (dir_handle_from, str_to_bytes(from_name)):
                    self.locations[filehandle] = (dir_handle_to, str_to_bytes(to_name))
        from_after_status, from_after = self.get_attributes4(dir_handle_from, auth=auth)
        to_after_status, to_after = self.get_attributes4(dir_handle_to, auth=auth)
        return {"status": response.status, "res": {"fromdir_wcc": wcc_data(from_after if from_after_status == const.NFS4_OK else None, from_before if from_status == const.NFS4_OK else None), "todir_wcc": wcc_data(to_after if to_after_status == const.NFS4_OK else None, to_before if to_status == const.NFS4_OK else None)}}

    @fh_check
    def link(self, file_handle, link_to_dir_handle, link_name, auth=None):
        if self.version == "3":
            return self.raw.link(file_handle, link_to_dir_handle, link_name, auth)
        if not isinstance(link_to_dir_handle, bytes):
            raise TypeError("file handle should be bytes")
        file_status, file_attributes = self.get_attributes4(file_handle, auth=auth)
        dir_status, dir_before = self.get_attributes4(link_to_dir_handle, auth=auth)
        response = self.with_filehandles(link_to_dir_handle, file_handle, self.raw.link_op(str_to_bytes(link_name)), tag=b"link", auth=auth, check=False)
        if response.status == const.NFS4_OK:
            self.locations[file_handle] = (link_to_dir_handle, str_to_bytes(link_name))
        after_status, after = self.get_attributes4(link_to_dir_handle, auth=auth)
        return {"status": response.status, "res": {"file_attributes": post_op_attributes(file_attributes if file_status == const.NFS4_OK else None), "linkdir_wcc": wcc_data(after if after_status == const.NFS4_OK else None, dir_before if dir_status == const.NFS4_OK else None)}}

    def read_directory(self, dir_handle, cookie, cookie_verf, dircount, maxcount, include_attributes, auth):
        requested = DIRECTORY_ATTRIBUTES if include_attributes else READDIR_ATTRIBUTES
        status, attributes = self.supported_attributes(dir_handle, requested, auth)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes())
        response = self.with_filehandle(dir_handle, self.raw.readdir_op(cookie, b"\0" * const.NFS4_VERIFIER_SIZE if cookie == 0 else verifier8(cookie_verf), dircount, maxcount, attributes), tag=b"readdirplus" if include_attributes else b"readdir", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, post_op_attributes())
        page = self.raw.operation_result(response, const.OP_READDIR)
        if include_attributes:
            for entry in page.entries:
                if const.FATTR4_FILEHANDLE in entry.attrs.attributes:
                    self.locations[entry.attrs.attributes[const.FATTR4_FILEHANDLE]] = (dir_handle, str_to_bytes(entry.name))
        dir_status, dir_attributes = self.get_attributes4(dir_handle, auth=auth)
        return {"status": const.NFS4_OK, "resok": {"dir_attributes": post_op_attributes(dir_attributes if dir_status == const.NFS4_OK else None), "cookieverf": page.cookieverf, "reply": {"entries": linked_entries(page.entries, include_attributes), "eof": page.eof}}}

    @fh_check
    def readdir(self, dir_handle, cookie=0, cookie_verf=b"0", count=4096, auth=None):
        return self.raw.readdir(dir_handle, cookie, cookie_verf, count, auth) if self.version == "3" else self.read_directory(dir_handle, cookie, cookie_verf, count, count, False, auth)

    @fh_check
    def readdirplus(self, dir_handle, cookie=0, cookie_verf=b"0", dircount=4096, maxcount=32768, auth=None):
        return self.raw.readdirplus(dir_handle, cookie, cookie_verf, dircount, maxcount, auth) if self.version == "3" else self.read_directory(dir_handle, cookie, cookie_verf, dircount, maxcount, True, auth)

    @fh_check
    def fsstat(self, file_handle, auth=None):
        if self.version == "3":
            return self.raw.fsstat(file_handle, auth=auth)
        status, attributes = self.get_attributes4(file_handle, FILESYSTEM_ATTRIBUTES, auth)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes())
        values = attributes.attributes
        return {"status": status, "resok": {"obj_attributes": post_op_attributes(attributes), "tbytes": values.get(const.FATTR4_SPACE_TOTAL, 0), "fbytes": values.get(const.FATTR4_SPACE_FREE, 0), "abytes": values.get(const.FATTR4_SPACE_AVAIL, 0), "tfiles": values.get(const.FATTR4_FILES_TOTAL, 0), "ffiles": values.get(const.FATTR4_FILES_FREE, 0), "afiles": values.get(const.FATTR4_FILES_AVAIL, 0), "invarsec": 0}}

    @fh_check
    def fsinfo(self, file_handle, auth=None):
        if self.version == "3":
            return self.raw.fsinfo(file_handle, auth=auth)
        status, attributes = self.get_attributes4(file_handle, FSINFO_ATTRIBUTES, auth)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes())
        values = attributes.attributes
        properties = 0
        if values.get(const.FATTR4_LINK_SUPPORT):
            properties |= v3.FSF3_LINK
        if values.get(const.FATTR4_SYMLINK_SUPPORT):
            properties |= v3.FSF3_SYMLINK
        if values.get(const.FATTR4_HOMOGENEOUS):
            properties |= v3.FSF3_HOMOGENEOUS
        if values.get(const.FATTR4_CANSETTIME):
            properties |= v3.FSF3_CANSETTIME
        max_read = values.get(const.FATTR4_MAXREAD, 1024 * 1024)
        max_write = values.get(const.FATTR4_MAXWRITE, 1024 * 1024)
        session = getattr(self.raw, "fore_chan_attrs", None)
        read_preferred = min(max_read, max(1, session.maxresponsesize - 4096)) if session is not None else max_read
        write_preferred = min(max_write, max(1, session.maxrequestsize - 4096)) if session is not None else max_write
        return {"status": status, "resok": {"obj_attributes": post_op_attributes(attributes), "rtmax": max_read, "rtpref": read_preferred, "rtmult": 1, "wtmax": max_write, "wtpref": write_preferred, "wtmult": 1, "dtpref": read_preferred, "maxfilesize": values.get(const.FATTR4_MAXFILESIZE, 0), "time_delta": nfs3_time(values.get(const.FATTR4_TIME_DELTA)), "properties": properties}}

    @fh_check
    def pathconf(self, file_handle, auth=None):
        if self.version == "3":
            return self.raw.pathconf(file_handle, auth=auth)
        status, attributes = self.get_attributes4(file_handle, PATHCONF_ATTRIBUTES, auth)
        if status != const.NFS4_OK:
            return response_failure(status, post_op_attributes())
        values = attributes.attributes
        return {"status": status, "resok": {"obj_attributes": post_op_attributes(attributes), "linkmax": values.get(const.FATTR4_MAXLINK, 0), "name_max": values.get(const.FATTR4_MAXNAME, 0), "no_trunc": values.get(const.FATTR4_NO_TRUNC, False), "chown_restricted": values.get(const.FATTR4_CHOWN_RESTRICTED, False), "case_insensitive": values.get(const.FATTR4_CASE_INSENSITIVE, False), "case_preserving": values.get(const.FATTR4_CASE_PRESERVING, True)}}

    @fh_check
    def commit(self, file_handle, count=0, offset=0, auth=None):
        if self.version == "3":
            return self.raw.commit(file_handle, count, offset, auth)
        before_status, before = self.get_attributes4(file_handle, auth=auth)
        response = self.with_filehandle(file_handle, self.raw.commit_op(offset, count), tag=b"commit", auth=auth, check=False)
        if response.status != const.NFS4_OK:
            return response_failure(response.status, wcc_data(before=before if before_status == const.NFS4_OK else None))
        after_status, after = self.get_attributes4(file_handle, auth=auth)
        return {"status": const.NFS4_OK, "resok": {"file_wcc": wcc_data(after if after_status == const.NFS4_OK else None, before if before_status == const.NFS4_OK else None), "verf": self.raw.operation_result(response, const.OP_COMMIT).writeverf}}


__all__ = ("NFSClient",)
