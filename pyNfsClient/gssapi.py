import struct
from hmac import compare_digest

from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5

from impacket.krb5 import constants, crypto
from impacket.krb5.gssapi import (
    KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_ACCEPTOR_SIGN, KG_USAGE_INITIATOR_SEAL, KG_USAGE_INITIATOR_SIGN,
    KRB_OID, MechIndepToken,
)

KRB5_AP_REQ = struct.pack("<H", 0x1)
KRB5_AP_REP = struct.pack("<H", 0x2)
KRB5_ERROR = struct.pack("<H", 0x3)

class KerberosGSSContext:
    """Kerberos GSS per-message context for contiguous mechanism tokens."""

    SENT_BY_ACCEPTOR = 0x01
    SEALED = 0x02
    ACCEPTOR_SUBKEY = 0x04

    def __init__(self, cipher, sessionKey, sequenceNumber=0, isAcceptor=False, sendSequenceNumber=None, receiveSequenceNumber=None):
        self.validateCipher(cipher, sessionKey)
        if sendSequenceNumber is None:
            sendSequenceNumber = sequenceNumber
        if receiveSequenceNumber is None:
            receiveSequenceNumber = sequenceNumber
        self.cipher = cipher
        self.sessionKey = sessionKey
        self.sendSequenceNumber = sendSequenceNumber
        self.receiveSequenceNumber = receiveSequenceNumber
        self.isAcceptor = isAcceptor
        self.usingAcceptorSubkey = False
        self.validateSequenceNumber(sendSequenceNumber)
        self.validateSequenceNumber(receiveSequenceNumber)

    def setAcceptorSubkey(self, cipher, sessionKey=None):
        """Use the subkey asserted by an acceptor in its AP-REP."""
        if sessionKey is None:
            sessionKey = cipher
            cipher = crypto._get_enctype_profile(sessionKey.enctype)
        self.validateCipher(cipher, sessionKey)
        self.cipher = cipher
        self.sessionKey = sessionKey
        self.usingAcceptorSubkey = True
        self.validateSequenceNumber(self.sendSequenceNumber)
        self.validateSequenceNumber(self.receiveSequenceNumber)

    def getMIC(self, data):
        """Return a MIC token and advance the local sending sequence."""
        self.validateSequenceNumber(self.sendSequenceNumber)
        if self.cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
            token = self.getRC4MIC(bytes(data))
        else:
            token = self.getAESMIC(bytes(data))
        self.sendSequenceNumber = (self.sendSequenceNumber + 1) & self.sequenceMask()
        return token

    def verifyMIC(self, data, token):
        """Verify a peer MIC token and advance the receiving sequence."""
        self.validateSequenceNumber(self.receiveSequenceNumber)
        if self.cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
            self.verifyRC4MIC(bytes(data), bytes(token))
        else:
            self.verifyAESMIC(bytes(data), bytes(token))
        self.receiveSequenceNumber = (self.receiveSequenceNumber + 1) & self.sequenceMask()
        return True

    def wrap(self, data, encrypt=True):
        """Return one contiguous Wrap token and advance the send sequence."""
        self.validateSequenceNumber(self.sendSequenceNumber)
        if self.cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
            token = self.wrapRC4(bytes(data), encrypt)
        else:
            token = self.wrapAES(bytes(data), encrypt)
        self.sendSequenceNumber = (self.sendSequenceNumber + 1) & self.sequenceMask()
        return token

    def unwrap(self, token):
        """Verify and unwrap one contiguous token from the peer."""
        self.validateSequenceNumber(self.receiveSequenceNumber)
        if self.cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
            data = self.unwrapRC4(bytes(token))
        else:
            data = self.unwrapAES(bytes(token))
        self.receiveSequenceNumber = (self.receiveSequenceNumber + 1) & self.sequenceMask()
        return data

    def validateCipher(self, cipher, sessionKey):
        if cipher.enctype != sessionKey.enctype:
            raise ValueError("Cipher and session key enctypes differ")
        if cipher.enctype not in (
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.rc4_hmac.value,
        ):
            raise ValueError(f"Unsupported Kerberos GSS enctype 0x{cipher.enctype:x}")

    def validateSequenceNumber(self, sequenceNumber):
        if not isinstance(sequenceNumber, int) or sequenceNumber < 0 or sequenceNumber > self.sequenceMask():
            raise ValueError("Invalid Kerberos GSS sequence number")

    def sequenceMask(self):
        if self.cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
            return 0xFFFFFFFF
        return 0xFFFFFFFFFFFFFFFF

    def checksumProfile(self):
        if self.cipher.enctype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            return crypto._SHA1AES128
        if self.cipher.enctype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            return crypto._SHA1AES256
        raise ValueError("RFC 4121 checksum requested for a non-AES context")

    def tokenFlags(self, senderIsAcceptor, sealed=False):
        return (self.SENT_BY_ACCEPTOR if senderIsAcceptor else 0) | (self.SEALED if sealed else 0) | (self.ACCEPTOR_SUBKEY if self.usingAcceptorSubkey else 0)

    def validateTokenFlags(self, flags, sealed):
        if flags != self.tokenFlags(not self.isAcceptor, sealed):
            raise ValueError("Kerberos GSS token direction or key flag mismatch")

    def signUsage(self, senderIsAcceptor):
        if senderIsAcceptor:
            return KG_USAGE_ACCEPTOR_SIGN
        return KG_USAGE_INITIATOR_SIGN

    def sealUsage(self, senderIsAcceptor):
        if senderIsAcceptor:
            return KG_USAGE_ACCEPTOR_SEAL
        return KG_USAGE_INITIATOR_SEAL

    def validateReceivedSequence(self, sequenceNumber):
        if sequenceNumber != self.receiveSequenceNumber:
            raise ValueError(f"Unexpected Kerberos GSS sequence number {sequenceNumber:d}, expected {self.receiveSequenceNumber:d}")

    def getAESMIC(self, data):
        header = struct.pack(">HB5sQ", 0x0404, self.tokenFlags(self.isAcceptor), b"\xff" * 5, self.sendSequenceNumber)
        return header + self.checksumProfile().checksum(self.sessionKey, self.signUsage(self.isAcceptor), data + header)

    def verifyAESMIC(self, data, token):
        if len(token) != 28 or token[:2] != b"\x04\x04" or token[3:8] != b"\xff" * 5:
            raise ValueError("Malformed RFC 4121 MIC token")
        self.checksumProfile().verify(self.sessionKey, self.signUsage(not self.isAcceptor), data + token[:16], token[16:])
        self.validateTokenFlags(token[2], False)
        self.validateReceivedSequence(struct.unpack(">Q", token[8:16])[0])

    def wrapAES(self, data, encrypt):
        if encrypt:
            header = struct.pack(">HBBHHQ", 0x0504, self.tokenFlags(self.isAcceptor, True), 0xFF, 0, 0, self.sendSequenceNumber)
            return header + self.cipher.encrypt(self.sessionKey, self.sealUsage(self.isAcceptor), data + header, None)
        checksumHeader = struct.pack(">HBBHHQ", 0x0504, self.tokenFlags(self.isAcceptor), 0xFF, 0, 0, self.sendSequenceNumber)
        return (
            checksumHeader[:4]
            + struct.pack(">H", self.checksumProfile().macsize)
            + checksumHeader[6:]
            + data
            + self.checksumProfile().checksum(self.sessionKey, self.sealUsage(self.isAcceptor), data + checksumHeader)
        )

    def unwrapAES(self, token):
        if len(token) < 28 or token[:2] != b"\x05\x04" or token[3] != 0xFF:
            raise ValueError("Malformed RFC 4121 Wrap token")
        flags, extraCount, rotationCount, sequenceNumber = struct.unpack(">B1xHHQ", token[2:16])
        sealed = bool(flags & self.SEALED)
        body = self.leftRotate(token[16:], rotationCount)
        if sealed:
            plaintext = self.cipher.decrypt(self.sessionKey, self.sealUsage(not self.isAcceptor), body)
            if len(plaintext) < 16 + extraCount:
                raise ValueError("Malformed RFC 4121 encrypted Wrap token")
            trailer = token[:6] + b"\x00\x00" + token[8:16]
            if not compare_digest(plaintext[-16:], trailer):
                raise ValueError("RFC 4121 encrypted Wrap header mismatch")
            data = plaintext[: -(16 + extraCount)] if extraCount else plaintext[:-16]
        else:
            if extraCount != self.checksumProfile().macsize or len(body) < extraCount:
                raise ValueError("Malformed RFC 4121 integrity Wrap token")
            data = body[:-extraCount]
            checksumHeader = token[:4] + b"\x00\x00\x00\x00" + token[8:16]
            self.checksumProfile().verify(self.sessionKey, self.sealUsage(not self.isAcceptor), data + checksumHeader, body[-extraCount:])
        self.validateTokenFlags(flags, sealed)
        self.validateReceivedSequence(sequenceNumber)
        return data

    def leftRotate(self, data, count):
        if not data:
            return data
        count %= len(data)
        return data[count:] + data[:count] if count else data

    def encodeRC4Token(self, data):
        return b"\x60" + MechIndepToken.encode_length(len(KRB_OID) + len(data)) + KRB_OID + data

    def decodeRC4Token(self, token):
        if len(token) < 2 or token[0] != 0x60:
            raise ValueError("Malformed RFC 4757 mechanism token")
        if token[1] < 0x80:
            tokenLength = token[1]
            dataOffset = 2
        else:
            lengthBytes = token[1] & 0x7F
            if lengthBytes == 0 or lengthBytes > 4 or len(token) < 2 + lengthBytes:
                raise ValueError("Malformed RFC 4757 mechanism token length")
            tokenLength = int.from_bytes(token[2:2 + lengthBytes], byteorder="big")
            dataOffset = 2 + lengthBytes
            if tokenLength < 0x80:
                raise ValueError("Non-canonical RFC 4757 mechanism token length")
        if len(token) != dataOffset + tokenLength or token[dataOffset:dataOffset + len(KRB_OID)] != KRB_OID:
            raise ValueError("Malformed RFC 4757 mechanism token body")
        return token[dataOffset + len(KRB_OID):]

    def rc4Checksum(self, keyUsage, header, data):
        return HMAC.new(HMAC.new(self.sessionKey.contents, b"signaturekey\0", MD5).digest(), MD5.new(struct.pack("<L", keyUsage) + header + data).digest(), MD5).digest()[:8]

    def rc4SequenceKey(self, checksum):
        return HMAC.new(HMAC.new(self.sessionKey.contents, struct.pack("<L", 0), MD5).digest(), checksum, MD5).digest()

    def rc4EncryptionKey(self, sequenceNumber):
        return HMAC.new(HMAC.new(bytes(value ^ 0xF0 for value in self.sessionKey.contents), struct.pack("<L", 0), MD5).digest(), struct.pack(">L", sequenceNumber), MD5).digest()

    def rc4Sequence(self, sequenceNumber, senderIsAcceptor):
        return struct.pack(">L", sequenceNumber) + (b"\xff" * 4 if senderIsAcceptor else b"\x00" * 4)

    def validateRC4Sequence(self, sequence, senderIsAcceptor):
        if sequence[4:] != (b"\xff" * 4 if senderIsAcceptor else b"\x00" * 4):
            raise ValueError("Kerberos GSS token direction mismatch")
        self.validateReceivedSequence(struct.unpack(">L", sequence[:4])[0])

    def getRC4MIC(self, data):
        header = b"\x01\x01\x11\x00\xff\xff\xff\xff"
        checksum = self.rc4Checksum(15, header, data)
        return self.encodeRC4Token(header + ARC4.new(self.rc4SequenceKey(checksum)).encrypt(self.rc4Sequence(self.sendSequenceNumber, self.isAcceptor)) + checksum)

    def verifyRC4MIC(self, data, token):
        innerToken = self.decodeRC4Token(token)
        if len(innerToken) != 24 or innerToken[:8] != b"\x01\x01\x11\x00\xff\xff\xff\xff":
            raise ValueError("Malformed RFC 4757 MIC token")
        if not compare_digest(self.rc4Checksum(15, innerToken[:8], data), innerToken[16:24]):
            raise crypto.InvalidChecksum("RFC 4757 MIC integrity failure")
        self.validateRC4Sequence(ARC4.new(self.rc4SequenceKey(innerToken[16:24])).decrypt(innerToken[8:16]), not self.isAcceptor)

    def wrapRC4(self, data, encrypt):
        paddedData = data + b"\x01"
        header = b"\x02\x01\x11\x00" + (b"\x10\x00" if encrypt else b"\xff\xff") + b"\xff\xff"
        confounder = crypto.get_random_bytes(8)
        checksum = self.rc4Checksum(13, header, confounder + paddedData)
        sequence = ARC4.new(self.rc4SequenceKey(checksum)).encrypt(self.rc4Sequence(self.sendSequenceNumber, self.isAcceptor))
        if encrypt:
            body = ARC4.new(self.rc4EncryptionKey(self.sendSequenceNumber)).encrypt(confounder + paddedData)
        else:
            body = confounder + paddedData
        return self.encodeRC4Token(header + sequence + checksum + body)

    def unwrapRC4(self, token):
        innerToken = self.decodeRC4Token(token)
        if len(innerToken) < 33 or innerToken[:4] != b"\x02\x01\x11\x00" or innerToken[4:6] not in (b"\x10\x00", b"\xff\xff") or innerToken[6:8] != b"\xff\xff":
            raise ValueError("Malformed RFC 4757 Wrap token")
        sequence = ARC4.new(self.rc4SequenceKey(innerToken[16:24])).decrypt(innerToken[8:16])
        sequenceNumber = struct.unpack(">L", sequence[:4])[0]
        if innerToken[4:6] == b"\x10\x00":
            body = ARC4.new(self.rc4EncryptionKey(sequenceNumber)).decrypt(innerToken[24:])
        else:
            body = innerToken[24:]
        if not compare_digest(self.rc4Checksum(13, innerToken[:8], body), innerToken[16:24]):
            raise crypto.InvalidChecksum("RFC 4757 Wrap integrity failure")
        self.validateRC4Sequence(sequence, not self.isAcceptor)
        if len(body) < 9 or body[-1] != 1:
            raise ValueError("Malformed RFC 4757 Wrap padding")
        return body[8:-1]
