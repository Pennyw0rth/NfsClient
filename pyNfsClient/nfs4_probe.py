import struct
from dataclasses import dataclass

from . import const as nfs3_const
from . import nfs4_const as const
from .portmap import Portmap
from .rpc import RPC, RPCAcceptError, RPCProtocolError
from .rpc_const import PROG_MISMATCH, PROG_UNAVAIL
from .xdrlib import Error as XDRError
from .xdrlib import Unpacker


PROBE_MINOR_VERSIONS = (2, 1, 0)
NFS_VERSIONS = ("3", "4.0", "4.1", "4.2")


@dataclass(frozen=True)
class NFSVersionDiscovery:
    supported: tuple[str, ...]
    inconclusive: tuple[tuple[str, Exception], ...]
    nfs3_port: int | None


def interpret_probe_response(response):
    unpacker = Unpacker(response)
    try:
        status = unpacker.unpack_int()
        if unpacker.unpack_opaque() != b"":
            raise RPCProtocolError("NFSv4 probe response tag does not match the request")
        result_count = unpacker.unpack_uint()
        if status == const.NFS4ERR_MINOR_VERS_MISMATCH:
            if result_count:
                raise RPCProtocolError("NFS4ERR_MINOR_VERS_MISMATCH probe response contains operation results")
            unpacker.done()
            return False
        if result_count > 1:
            raise RPCProtocolError("NFSv4 probe response contains too many operation results")
        if result_count:
            if unpacker.unpack_int() != const.OP_PUTROOTFH:
                raise RPCProtocolError("NFSv4 probe response contains an unexpected operation")
            result_status = unpacker.unpack_int()
            if result_status != status:
                raise RPCProtocolError("NFSv4 probe operation status does not match the COMPOUND status")
        elif status == const.NFS4_OK:
            raise RPCProtocolError("successful NFSv4 probe response contains no operation result")
        unpacker.done()
        return True
    except (EOFError, XDRError) as e:
        raise RPCProtocolError("malformed NFSv4 probe response") from e


def probe_minor_version(host, minor_version, auth=None, port=2049, timeout=5):
    if not isinstance(minor_version, int) or not 0 <= minor_version <= 0xFFFFFFFF:
        raise ValueError("minor_version must be an unsigned 32-bit integer")
    rpc = RPC(host, port, timeout)
    try:
        rpc.connect()
        return interpret_probe_response(rpc.request(const.NFS_PROGRAM, const.NFS_V4, const.NFS4_PROCEDURE_COMPOUND, data=struct.pack("!4L", 0, minor_version, 1, const.OP_PUTROOTFH), auth=auth))
    finally:
        rpc.disconnect()


def discover_minor_versions(host, auth=None, port=2049, timeout=5):
    return tuple(minor_version for minor_version in PROBE_MINOR_VERSIONS if probe_minor_version(host, minor_version, auth, port, timeout))


def probe_nfs3(host, auth=None, port=2049, timeout=5):
    rpc = RPC(host, port, timeout)
    try:
        rpc.connect()
        try:
            response = rpc.request(nfs3_const.NFS_PROGRAM, nfs3_const.NFS_V3, nfs3_const.NFS3_PROCEDURE_NULL, auth=auth)
        except RPCAcceptError as e:
            if e.status in {PROG_UNAVAIL, PROG_MISMATCH}:
                return False
            raise
        if response:
            raise RPCProtocolError("NFSv3 NULL probe returned unexpected result data")
        return True
    finally:
        rpc.disconnect()


def discover_rpcbind_nfs3_port(host, timeout=5, rpcbind_port=111):
    portmap = Portmap(host, timeout=timeout, port=rpcbind_port)
    try:
        portmap.connect()
        for mapping in portmap.dump():
            if mapping["program"] == nfs3_const.NFS_PROGRAM and mapping["version"] == nfs3_const.NFS_V3 and mapping["protocol"] == "tcp" and mapping["port"]:
                return mapping["port"]
        return None
    finally:
        portmap.disconnect()


def discover_nfs_versions(host, auth=None, port=2049, timeout=5, rpcbind_port=111):
    recognized = set()
    inconclusive = []
    nfs3_port = None
    try:
        mapped_nfs3_port = discover_rpcbind_nfs3_port(host, timeout, rpcbind_port)
    except Exception as e:
        inconclusive.append(("rpcbind", e))
        mapped_nfs3_port = None

    candidate_ports = []
    if mapped_nfs3_port is not None:
        candidate_ports.append(mapped_nfs3_port)
    if port not in candidate_ports:
        candidate_ports.append(port)
    for candidate_port in candidate_ports:
        try:
            if probe_nfs3(host, auth, candidate_port, timeout) and nfs3_port is None:
                nfs3_port = candidate_port
                recognized.add("3")
        except Exception as e:
            inconclusive.append((f"3@{candidate_port}", e))

    for minor_version in PROBE_MINOR_VERSIONS:
        version = f"4.{minor_version}"
        try:
            if probe_minor_version(host, minor_version, auth, port, timeout):
                recognized.add(version)
        except Exception as e:
            inconclusive.append((version, e))
    return NFSVersionDiscovery(tuple(version for version in NFS_VERSIONS if version in recognized), tuple(inconclusive), nfs3_port)
