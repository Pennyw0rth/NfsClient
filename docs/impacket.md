# Impacket changes used by pyNfsClient

The companion Impacket repository contains three small Kerberos
interoperability commits. NFS RPC, NFSv4 sessions, and the stateful GSS token
engine remain in pyNfsClient; Impacket is not being turned into an NFS client.

## AS reply decoding

Commits `11ae7a4b` and `aa597819` change two call sites:

- `impacket/krb5/ccache.py` when creating a cache from an AS reply
- `impacket/krb5/kerberosv5.py` when obtaining a TGT

Both sites first decode decrypted reply data as `EncASRepPart`. If pyasn1
reports a tag mismatch, they directly retry the same bytes as `EncTGSRepPart`.
There is deliberately no `decodeASRepPart` wrapper because only these two
callers need the compatibility branch and the wire alternatives are visible at
the point of use.

[RFC 4120 section 5.4.2](https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2)
allows the application tag normally used by `EncTGSRepPart` to appear in an
AS-REP for compatibility. Without the fallback, a standards-permitted KDC
reply fails before Impacket can obtain the session key or create a credential
cache. Only the ASN.1 decoding mismatch is caught; decryption and other errors
still propagate.

## TGS authenticator checksum

Commit `cf6b0b0a` changes `getKerberosTGS` so the complete KDC request body is
built before the PA-TGS-REQ AP-REQ. It then:

1. DER-encodes the `KDC-REQ-BODY` with its standalone ASN.1 tag.
2. Selects the keyed checksum type associated with the TGT session-key
   enctype.
3. Computes the checksum with Kerberos key usage 6 and places it in the
   authenticator.
4. Encrypts that authenticator with key usage 7, as before.

This ordering matters because the authenticator checksum covers the exact
encoded request body, including the final service name, nonce, options, realm,
and requested enctypes. [RFC 4120 section
3.3.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3) defines that
checksum, and [section
5.5.1](https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1) defines the AP-REQ
authenticator structure and encryption.

The mapping uses the checksum profiles defined for DES3, AES128, AES256, and
RC4. Microsoft's [MS-KILE checksum-type
list](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/c6dabc82-0792-4475-a44e-ae9b640d2613)
confirms the interoperable AES and RC4 checksum types, while [MS-KILE key usage
numbers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b760e935-5fb0-4380-a60a-52c267563a61)
defers standard Kerberos usages to RFC 4120. Tests verify the encoded checksum
and leave unsupported legacy enctypes on Impacket's prior no-checksum path.

## Why the stateful GSS engine is not in Impacket

The initial implementation added stateful GSS behavior beside Impacket's
existing GSS helpers. It was moved to `pyNfsClient/gssapi.py` because its state
belongs to one RPCSEC_GSS connection and is not a general Kerberos ticket
function.

The local `KerberosGSSContext` provides behavior the existing one-shot token
helpers do not combine into a reusable context:

- independent send and receive sequence counters;
- acceptor-subkey adoption after mutual authentication;
- AES and RC4 MIC, integrity-wrap, and privacy-wrap processing;
- token direction, sequence, header, rotation, padding, and checksum
  validation;
- the contiguous-token form required by RPCSEC_GSS.

RPCSEC_GSS itself owns request replay through the sequence number in the RPC
credential and its negotiated replay window. For that reason, the Kerberos GSS
token layer validates integrity and direction but does not require contiguous
peer token sequence numbers for RPC replies. This follows [RFC
2203](https://www.rfc-editor.org/rfc/rfc2203), with Kerberos token formats from
[RFC 4121](https://www.rfc-editor.org/rfc/rfc4121) and [RFC
4757](https://www.rfc-editor.org/rfc/rfc4757).

Microsoft's [MS-KILE cryptographic-material
section](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/7a7b081d-c0c6-46f4-acbf-a439664270b8)
also documents the important interoperability detail that an AP-REP acceptor
subkey becomes the session key under mutual authentication, especially for
AES. The pyNfsClient context applies that subkey before protecting NFS RPC
traffic.

## Scope and dependency boundary

No stateful GSS class remains in the Impacket branch. pyNfsClient imports
Impacket only from the optional Kerberos modules. AUTH_NONE and AUTH_SYS use
the base installation without Impacket.
