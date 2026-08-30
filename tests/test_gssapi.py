import unittest
from unittest.mock import patch

from impacket.krb5 import constants, crypto

from pyNfsClient.gssapi import KRB5_AP_REP, KRB5_AP_REQ, KRB5_ERROR, KerberosGSSContext


class KerberosGSSContextTests(unittest.TestCase):
    def test_token_identifiers(self):
        self.assertEqual(KRB5_AP_REQ, b"\x01\x00")
        self.assertEqual(KRB5_AP_REP, b"\x02\x00")
        self.assertEqual(KRB5_ERROR, b"\x03\x00")

    def test_rejects_invalid_configuration(self):
        with self.assertRaises(ValueError):
            KerberosGSSContext(crypto._AES128CTS, crypto.Key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, b"K" * 32))
        with self.assertRaises(ValueError):
            KerberosGSSContext(crypto._DES3CBC, crypto.Key(constants.EncryptionTypes.des3_cbc_sha1_kd.value, b"K" * 24))
        with self.assertRaises(ValueError):
            KerberosGSSContext(crypto._AES128CTS, crypto.Key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, b"K" * 16), sequenceNumber=-1)

    def test_aes_mic_both_enctypes_and_directions(self):
        for cipher, key in (
            (crypto._AES128CTS, crypto.Key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, b"1" * 16)),
            (crypto._AES256CTS, crypto.Key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, b"2" * 32)),
        ):
            for senderIsAcceptor in (False, True):
                with self.subTest(enctype=cipher.enctype, senderIsAcceptor=senderIsAcceptor):
                    sender = KerberosGSSContext(cipher, key, sequenceNumber=7, isAcceptor=senderIsAcceptor)
                    receiver = KerberosGSSContext(cipher, key, sequenceNumber=7, isAcceptor=not senderIsAcceptor)
                    token = sender.getMIC(b"message")

                    self.assertEqual(token[:2], b"\x04\x04")
                    self.assertEqual(bool(token[2] & KerberosGSSContext.SENT_BY_ACCEPTOR), senderIsAcceptor)
                    self.assertTrue(receiver.verifyMIC(b"message", token))
                    self.assertEqual(sender.sendSequenceNumber, 8)
                    self.assertEqual(receiver.receiveSequenceNumber, 8)

    def test_supports_distinct_negotiated_sequences(self):
        key = crypto.Key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, b"Q" * 16)
        initiator = KerberosGSSContext(crypto._AES128CTS, key, sendSequenceNumber=5, receiveSequenceNumber=9)
        acceptor = KerberosGSSContext(crypto._AES128CTS, key, isAcceptor=True, sendSequenceNumber=9, receiveSequenceNumber=5)

        self.assertTrue(acceptor.verifyMIC(b"request", initiator.getMIC(b"request")))
        self.assertTrue(initiator.verifyMIC(b"reply", acceptor.getMIC(b"reply")))

    def test_aes_wrap_both_directions_and_services(self):
        for senderIsAcceptor in (False, True):
            for encrypt in (False, True):
                with self.subTest(senderIsAcceptor=senderIsAcceptor, encrypt=encrypt):
                    key = crypto.Key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, b"K" * 32)
                    sender = KerberosGSSContext(crypto._AES256CTS, key, sequenceNumber=11, isAcceptor=senderIsAcceptor)
                    receiver = KerberosGSSContext(crypto._AES256CTS, key, sequenceNumber=11, isAcceptor=not senderIsAcceptor)
                    token = sender.wrap(b"contiguous-token", encrypt=encrypt)

                    self.assertEqual(token[:2], b"\x05\x04")
                    self.assertEqual(bool(token[2] & KerberosGSSContext.SEALED), encrypt)
                    self.assertEqual(receiver.unwrap(token), b"contiguous-token")

    def test_aes_unwrap_supports_nonzero_rrc(self):
        for encrypt in (False, True):
            with self.subTest(encrypt=encrypt):
                key = crypto.Key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, b"R" * 16)
                sender = KerberosGSSContext(crypto._AES128CTS, key, sequenceNumber=3)
                receiver = KerberosGSSContext(crypto._AES128CTS, key, sequenceNumber=3, isAcceptor=True)
                token = sender.wrap(b"rotate-me", encrypt=encrypt)
                rotationCount = 5
                body = token[16:]
                rotated = body[-rotationCount:] + body[:-rotationCount]
                token = token[:6] + rotationCount.to_bytes(2, "big") + token[8:16] + rotated

                self.assertEqual(receiver.unwrap(token), b"rotate-me")

    def test_aes_rejects_tampering_sequence_and_direction(self):
        key = crypto.Key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, b"T" * 16)
        sender = KerberosGSSContext(crypto._AES128CTS, key, sequenceNumber=9)
        token = bytearray(sender.getMIC(b"message"))
        token[-1] ^= 1
        receiver = KerberosGSSContext(crypto._AES128CTS, key, sequenceNumber=9, isAcceptor=True)

        with self.assertRaises(crypto.InvalidChecksum):
            receiver.verifyMIC(b"message", token)
        self.assertEqual(receiver.receiveSequenceNumber, 9)

        token = KerberosGSSContext(crypto._AES128CTS, key, sequenceNumber=9).getMIC(b"message")
        with self.assertRaises(ValueError):
            KerberosGSSContext(crypto._AES128CTS, key, sequenceNumber=10, isAcceptor=True).verifyMIC(b"message", token)
        with self.assertRaises(ValueError):
            KerberosGSSContext(crypto._AES128CTS, key, sequenceNumber=9).verifyMIC(b"message", token)

    def test_rejects_reserved_token_flags(self):
        key = crypto.Key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, b"F" * 16)

        with self.assertRaises(ValueError):
            KerberosGSSContext(crypto._AES128CTS, key, sequenceNumber=1, isAcceptor=True).validateTokenFlags(0x08, False)

    def test_uses_acceptor_subkey(self):
        sessionKey = crypto.Key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, b"S" * 16)
        acceptorSubkey = crypto.Key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, b"A" * 32)
        sender = KerberosGSSContext(crypto._AES128CTS, sessionKey, sequenceNumber=4)
        receiver = KerberosGSSContext(crypto._AES128CTS, sessionKey, sequenceNumber=4, isAcceptor=True)
        sender.setAcceptorSubkey(crypto._AES256CTS, acceptorSubkey)
        receiver.setAcceptorSubkey(acceptorSubkey)

        mic = sender.getMIC(b"subkey")
        self.assertTrue(mic[2] & KerberosGSSContext.ACCEPTOR_SUBKEY)
        self.assertTrue(receiver.verifyMIC(b"subkey", mic))

        sender = KerberosGSSContext(crypto._AES128CTS, sessionKey, sequenceNumber=5, isAcceptor=True)
        receiver = KerberosGSSContext(crypto._AES128CTS, sessionKey, sequenceNumber=5)
        sender.setAcceptorSubkey(crypto._AES256CTS, acceptorSubkey)
        receiver.setAcceptorSubkey(crypto._AES256CTS, acceptorSubkey)
        token = sender.wrap(b"subkey-wrap")
        self.assertTrue(token[2] & KerberosGSSContext.ACCEPTOR_SUBKEY)
        self.assertEqual(receiver.unwrap(token), b"subkey-wrap")

    def test_rc4_rfc4757_deterministic_tokens(self):
        key = crypto.Key(constants.EncryptionTypes.rc4_hmac.value, bytes(range(16)))

        self.assertEqual(KerberosGSSContext(crypto._RC4, key, sequenceNumber=0x01020304).getMIC(b"hello").hex(), "602306092a864886f71201020201011100ffffffffaef216d6c919accbae863ad4c3bf1160")
        with patch("pyNfsClient.gssapi.crypto.get_random_bytes", return_value=b"abcdefgh"):
            self.assertEqual(KerberosGSSContext(crypto._RC4, key, sequenceNumber=0x01020304).wrap(b"hello").hex(), "603106092a864886f712010202020111001000fffffa3876cd26b9d3b1efee66a29285056322448579d9593f62477e1899e1cf")
        with patch("pyNfsClient.gssapi.crypto.get_random_bytes", return_value=b"abcdefgh"):
            self.assertEqual(KerberosGSSContext(crypto._RC4, key, sequenceNumber=0x01020304).wrap(b"hello", encrypt=False).hex(), "603106092a864886f71201020202011100ffffffff6b9b6fbb489e0eca2e7107a9c861d6d6616263646566676868656c6c6f01")

    def test_rc4_round_trips_both_directions_and_services(self):
        key = crypto.Key(constants.EncryptionTypes.rc4_hmac.value, b"C" * 16)
        for senderIsAcceptor in (False, True):
            sender = KerberosGSSContext(crypto._RC4, key, sequenceNumber=12, isAcceptor=senderIsAcceptor)
            receiver = KerberosGSSContext(crypto._RC4, key, sequenceNumber=12, isAcceptor=not senderIsAcceptor)
            self.assertTrue(receiver.verifyMIC(b"rc4-mic", sender.getMIC(b"rc4-mic")))

            for encrypt in (False, True):
                with self.subTest(senderIsAcceptor=senderIsAcceptor, encrypt=encrypt):
                    token = sender.wrap(b"rc4-wrap", encrypt=encrypt)
                    self.assertEqual(token[0], 0x60)
                    self.assertEqual(receiver.unwrap(token), b"rc4-wrap")

    def test_rc4_rejects_tampering_sequence_and_direction(self):
        key = crypto.Key(constants.EncryptionTypes.rc4_hmac.value, b"D" * 16)
        token = bytearray(KerberosGSSContext(crypto._RC4, key, sequenceNumber=2).wrap(b"message"))
        token[-1] ^= 1
        receiver = KerberosGSSContext(crypto._RC4, key, sequenceNumber=2, isAcceptor=True)

        with self.assertRaises(crypto.InvalidChecksum):
            receiver.unwrap(token)
        self.assertEqual(receiver.receiveSequenceNumber, 2)

        token = KerberosGSSContext(crypto._RC4, key, sequenceNumber=2).getMIC(b"message")
        with self.assertRaises(ValueError):
            KerberosGSSContext(crypto._RC4, key, sequenceNumber=3, isAcceptor=True).verifyMIC(b"message", token)
        with self.assertRaises(ValueError):
            KerberosGSSContext(crypto._RC4, key, sequenceNumber=2).verifyMIC(b"message", token)


if __name__ == "__main__":
    unittest.main(verbosity=1)
