import struct

from . import nfs4_const as const
from .rpc import RPC, RPCProtocolError
from .xdrlib import Error as XDRError
from .xdrlib import Unpacker


PROBE_MINOR_VERSIONS = (2, 1, 0)


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
