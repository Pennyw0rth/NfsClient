import datetime
import ipaddress
import os
import secrets
import socket
import struct
from binascii import unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REP, AP_REQ, Authenticator, EncAPRepPart, TGS_REP, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import (
    CheckSumField, GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG,
    KRB_OID, MechIndepToken,
)
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.keytab import Enctype, Keytab
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import ASN1_AID, ASN1_OID, TypesMech, asn1encode

from .gssapi import KRB5_AP_REP, KRB5_AP_REQ, KRB5_ERROR, KerberosGSSContext


class KerberosCredentialError(Exception):
    pass


class KerberosInitiator:
    def __init__(self, host, credentials=None):
        self.host = host
        self.credentials = {} if credentials is None else dict(credentials)
        self.context = None
        self.cipher = None
        self.session_key = None
        self.authenticator_time = None
        self.authenticator_usec = None
        self.send_sequence = None

    def start(self):
        tgs = self.get_service_ticket()
        self.cipher = tgs["cipher"]
        self.session_key = tgs["sessionKey"]
        return self.build_ap_request(tgs["KDC_REP"])

    def step(self, token):
        if not token:
            raise KerberosCredentialError("Kerberos mutual authentication returned no AP-REP token")
        ap_rep = decoder.decode(self.unwrap_initial_token(token), asn1Spec=AP_REP())[0]
        plaintext = self.cipher.decrypt(self.session_key, 12, ap_rep["enc-part"]["cipher"])
        reply = decoder.decode(plaintext, asn1Spec=EncAPRepPart())[0]
        if KerberosTime.from_asn1(reply["ctime"]) != self.authenticator_time or int(reply["cusec"]) != self.authenticator_usec:
            raise KerberosCredentialError("Kerberos AP-REP does not match the AP-REQ authenticator")

        receive_sequence = int(reply["seq-number"]) if reply["seq-number"].hasValue() else 0
        self.context = KerberosGSSContext(self.cipher, self.session_key, sendSequenceNumber=self.send_sequence, receiveSequenceNumber=receive_sequence)
        if reply["subkey"].hasValue():
            keytype = int(reply["subkey"]["keytype"])
            self.context.setAcceptorSubkey(_enctype_table[keytype](), Key(keytype, reply["subkey"]["keyvalue"].asOctets()))
        return None

    def get_service_ticket(self):
        realm, username = self.principal_parts()
        spn = self.service_principal(realm)
        if self.credentials.get("tgs") is not None:
            return self.require_ticket(self.credentials["tgs"], "TGS")

        tgt = self.credentials.get("tgt")
        ccache = self.load_ccache()
        if ccache is not None:
            realm = realm or ccache.principal.realm["data"].decode("utf-8")
            spn = self.service_principal(realm)
            cached_service = ccache.getCredential(spn, anySPN=False)
            if cached_service is not None:
                return cached_service.toTGS(spn)
            cached_tgt = ccache.getCredential(f"krbtgt/{realm}@{realm}", anySPN=False)
            if cached_tgt is not None:
                tgt = cached_tgt.toTGT()
            if not username and ccache.principal.components:
                username = ccache.principal.components[0]["data"].decode("utf-8")

        if not realm:
            raise KerberosCredentialError("Kerberos realm is required when no usable credential cache is available")
        if tgt is None:
            if not username:
                raise KerberosCredentialError("Kerberos username is required when no TGT is supplied")
            lmhash, nthash, aes_key = self.secret_keys(username, realm)
            tgt_rep, cipher, old_session_key, session_key = getKerberosTGT(
                Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value),
                self.credentials.get("password", ""),
                realm,
                lmhash,
                nthash,
                aes_key,
                self.credentials.get("kdc_host"),
            )
            tgt = {"KDC_REP": tgt_rep, "cipher": cipher, "sessionKey": session_key}
        else:
            tgt = self.require_ticket(tgt, "TGT")

        tgs_rep, cipher, old_session_key, session_key = getKerberosTGS(
            Principal(spn.split("@", 1)[0], type=constants.PrincipalNameType.NT_SRV_INST.value),
            realm,
            self.credentials.get("kdc_host"),
            tgt["KDC_REP"],
            tgt["cipher"],
            tgt["sessionKey"],
        )
        return {"KDC_REP": tgs_rep, "cipher": cipher, "sessionKey": session_key}

    def principal_parts(self):
        username = self.credentials.get("username", "")
        realm = self.credentials.get("realm") or self.credentials.get("domain", "")
        if "@" in username:
            username, username_realm = username.rsplit("@", 1)
            realm = realm or username_realm
        return realm.upper(), username

    def service_principal(self, realm):
        if self.credentials.get("spn"):
            return self.credentials["spn"] if "@" in self.credentials["spn"] else f"{self.credentials['spn']}@{realm}"
        hostname = self.credentials.get("hostname") or socket.getfqdn(self.host)
        if not hostname:
            raise KerberosCredentialError("Kerberos authentication to an IP address requires hostname or an exact spn")
        try:
            ipaddress.ip_address(hostname)
        except ValueError as e:
            pass
        else:
            raise KerberosCredentialError("Kerberos authentication to an IP address requires hostname or an exact spn")
        return f"{self.credentials.get('service', 'nfs')}/{hostname}@{realm}"

    def load_ccache(self):
        cache_name = self.credentials.get("ccache")
        if cache_name is None and self.credentials.get("use_cache", True):
            cache_name = os.environ.get("KRB5CCNAME")
        if not cache_name:
            return None
        if cache_name.startswith("FILE:"):
            cache_name = cache_name[5:]
        return CCache.loadFile(cache_name)

    def secret_keys(self, username, realm):
        lmhash = self.decode_hex(self.credentials.get("lmhash", b""), "LM hash")
        nthash = self.decode_hex(self.credentials.get("nthash", b""), "NT hash")
        aes_key = self.decode_hex(self.credentials.get("aes_key", b""), "AES key")
        if self.credentials.get("hashes") and not nthash:
            lmhash_text, nthash_text = self.credentials["hashes"].split(":", 1)
            lmhash = self.decode_hex(lmhash_text, "LM hash")
            nthash = self.decode_hex(nthash_text, "NT hash")
        if self.credentials.get("keytab"):
            keyblock = Keytab.loadFile(self.credentials["keytab"]).getKey(f"{username}@{realm}", ignoreRealm=False)
            if keyblock is None:
                raise KerberosCredentialError(f"principal {username}@{realm} is not present in the keytab")
            if keyblock["keytype"] in (Enctype.AES128.value, Enctype.AES256.value):
                aes_key = keyblock["keyvalue"]["data"]
            elif keyblock["keytype"] == Enctype.RC4.value:
                nthash = keyblock["keyvalue"]["data"]
            else:
                raise KerberosCredentialError(f"unsupported keytab enctype {keyblock['keytype']}")
        return lmhash, nthash, aes_key

    def build_ap_request(self, encoded_tgs):
        decoded_tgs = decoder.decode(encoded_tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decoded_tgs["ticket"])
        ap_req = AP_REQ()
        ap_req["pvno"] = 5
        ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req["ap-options"] = constants.encodeFlags([constants.APOptions.mutual_required.value])
        seq_set(ap_req, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = decoded_tgs["crealm"].asOctets()
        client_name = Principal()
        client_name.from_asn1(decoded_tgs, "crealm", "cname")
        seq_set(authenticator, "cname", client_name.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.authenticator_time = now.replace(tzinfo=None, microsecond=0)
        self.authenticator_usec = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)
        authenticator["cusec"] = self.authenticator_usec
        authenticator["cksum"] = noValue
        authenticator["cksum"]["cksumtype"] = 0x8003
        checksum = CheckSumField()
        checksum["Lgth"] = 16
        checksum["Flags"] = GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
        authenticator["cksum"]["checksum"] = checksum.getData()
        self.send_sequence = secrets.randbits(32)
        authenticator["seq-number"] = self.send_sequence

        ap_req["authenticator"] = noValue
        ap_req["authenticator"]["etype"] = self.cipher.enctype
        ap_req["authenticator"]["cipher"] = self.cipher.encrypt(self.session_key, 11, encoder.encode(authenticator), None)
        mechanism = struct.pack("B", ASN1_OID) + asn1encode(TypesMech["KRB5 - Kerberos 5"])
        return struct.pack("B", ASN1_AID) + asn1encode(mechanism + KRB5_AP_REQ + encoder.encode(ap_req))

    @staticmethod
    def unwrap_initial_token(token):
        if token.startswith(b"\x60"):
            mechanism = MechIndepToken.from_bytes(token)
            if mechanism.token_oid != KRB_OID:
                raise KerberosCredentialError("GSS response uses an unexpected mechanism OID")
            token = mechanism.data
        if token.startswith(KRB5_ERROR):
            raise KerberosCredentialError("Kerberos acceptor returned a KRB-ERROR token")
        if token.startswith(KRB5_AP_REP):
            return token[len(KRB5_AP_REP) :]
        if token.startswith(b"\x6f"):
            return token
        raise KerberosCredentialError("GSS response is not a Kerberos AP-REP token")

    @staticmethod
    def require_ticket(ticket, name):
        if not isinstance(ticket, dict) or not {"KDC_REP", "cipher", "sessionKey"}.issubset(ticket):
            raise KerberosCredentialError(f"{name} must contain KDC_REP, cipher, and sessionKey")
        return ticket

    @staticmethod
    def decode_hex(value, label):
        if not value:
            return b""
        if isinstance(value, bytes):
            return value
        try:
            return unhexlify(value)
        except (TypeError, ValueError) as e:
            raise KerberosCredentialError(f"{label} must be hexadecimal") from e
