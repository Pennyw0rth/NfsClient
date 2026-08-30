from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import Authenticator, TGS_REP, seq_set
from impacket.krb5.gssapi import CheckSumField, GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG
from impacket.krb5.types import Principal

from pyNfsClient.kerberos import KerberosInitiator


def encoded_service_ticket():
    reply = TGS_REP()
    reply["pvno"] = 5
    reply["msg-type"] = constants.ApplicationTagNumbers.TGS_REP.value
    reply["crealm"] = "NFS.TEST"
    seq_set(reply, "cname", Principal("nfsclient", type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    reply["ticket"] = noValue
    reply["ticket"]["tkt-vno"] = 5
    reply["ticket"]["realm"] = "NFS.TEST"
    seq_set(reply["ticket"], "sname", Principal("nfs/nfs4.nfs.test", type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    reply["ticket"]["enc-part"] = noValue
    reply["ticket"]["enc-part"]["etype"] = constants.EncryptionTypes.rc4_hmac.value
    reply["ticket"]["enc-part"]["cipher"] = b"ticket"
    reply["enc-part"] = noValue
    reply["enc-part"]["etype"] = constants.EncryptionTypes.rc4_hmac.value
    reply["enc-part"]["cipher"] = b"reply"
    return encoder.encode(reply)


def test_rpcsec_gss_disables_gss_replay_and_sequence_flags():
    class Cipher:
        enctype = constants.EncryptionTypes.rc4_hmac.value
        encrypted = None

        @classmethod
        def encrypt(cls, key, usage, data, iv):
            cls.encrypted = (usage, data)
            return b"encrypted-authenticator"

    initiator = KerberosInitiator("nfs4.nfs.test")
    initiator.cipher = Cipher()
    initiator.session_key = object()
    initiator.build_ap_request(encoded_service_ticket())
    assert Cipher.encrypted[0] == 11
    authenticator = decoder.decode(Cipher.encrypted[1], asn1Spec=Authenticator())[0]
    assert CheckSumField(authenticator["cksum"]["checksum"].asOctets())["Flags"] == (GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG)
    assert not CheckSumField(authenticator["cksum"]["checksum"].asOctets())["Flags"] & (GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG)
