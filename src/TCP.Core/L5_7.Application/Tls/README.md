# TLS

Namespace `TCP.L5_7.Application.Tls`. A learning implementation of TLS 1.3
(RFC 8446) and TLS 1.2 (RFC 5246), client and server, running over this stack's
`TcpConnection`. The protocol logic (records, handshake state machines, key
schedule, alerts) is written here. The cryptographic primitives come from
`System.Security.Cryptography`: `ECDiffieHellman`, `AesGcm`, `ChaCha20Poly1305`,
`HKDF`, `HMAC`/SHA-2, `ECDsa`/`RSA` and `X509Certificate2`.

It is a teaching implementation: it has not been reviewed or hardened, and
nothing here is constant-time beyond what the platform primitives provide.

## Where TLS sits

```text
application bytes          TlsConnection.Send / Read / DataAvailable
        |
  record layer             frames, encrypts (AEAD) and authenticates records
  handshake / alerts       negotiates version, suite, keys; proves the server's identity
        |
TCP byte stream            TcpConnection.Send / Read / DataAvailable
```

TCP gives a reliable, ordered byte stream, but no secrecy and no proof of who is
on the other end. TLS adds both. It cuts the stream into records. A handshake
authenticates the server with a certificate and agrees fresh keys with ephemeral
Diffie-Hellman. Every record after that is encrypted and authenticated with
those keys.

## Using it

```csharp
var certificate = TlsCertificates.CreateSelfSigned("localhost"); // ECDSA P-256

// Server: wrap each accepted TCP connection.
stack.Tcp.Listen(443, tcp =>
{
    var tls = TlsConnection.AuthenticateAsServer(tcp, new TlsServerOptions
    {
        Certificate = certificate,
        ApplicationProtocols = ["h2", "http/1.1"],
    });
    tls.HandshakeCompleted += c => Console.WriteLine($"{c.Version} {c.CipherSuite} ALPN {c.ApplicationProtocol}");
    tls.DataAvailable += c => { var bytes = new byte[c.Available]; c.Read(bytes); c.Send(bytes); };
    tls.ReadClosed += c => c.Close();
});

// Client: start on a TCP connection; ClientHello goes out once TCP is established.
var client = TlsConnection.AuthenticateAsClient(stack.Tcp.Connect(address, 443), new TlsClientOptions
{
    TargetHost = "localhost",
    CertificateValidation = (leaf, _) => leaf.Thumbprint == certificate.Thumbprint, // Trust the self-signed cert.
});
client.HandshakeCompleted += c => c.Send("hello"u8);
```

`TlsConnection` has the same event-driven shape and threading contract as
`TcpConnection`: every call and callback runs on the stack's protocol thread,
and callbacks may call back in. `Close()` sends close_notify and then closes
TCP's sending side. A TCP FIN that arrives without close_notify is reported as
truncation in `FailureReason`.

## Folders

| Folder | Contents |
| --- | --- |
| `.` | `TlsConnection` (TCP binding), `TlsEngine` (the protocol, independent of any transport), options, `TlsCertificates` |
| `Wire` | `TlsReader`/`TlsWriter`: the presentation language's big-endian integers and length-prefixed vectors |
| `Records` | record framing, `Tls13RecordProtection` and `Tls12RecordProtection` (AEAD, per-record nonces), `RecordLayer` |
| `Handshake` | message reassembly, transcript hash, and the state machines: `ClientHandshake`/`ServerHandshake` settle the version, then `Tls13*`/`Tls12*` finish |
| `Handshake/Messages` | ClientHello, ServerHello (and HelloRetryRequest), Certificate, CertificateVerify, ServerKeyExchange, and small messages |
| `Extensions` | supported_versions, key_share, supported_groups, signature_algorithms, ALPN, SNI, record_size_limit, extended_master_secret, renegotiation_info, cookie |
| `Cryptography` | cipher suites, `Tls13KeySchedule` (HKDF-Extract, HKDF-Expand-Label, Derive-Secret), `Tls12Prf`, ECDHE, signatures |
| `Alerts` | alert levels and descriptions; `TlsAlertException` turns any protocol error into a fatal alert |
| `Demos` | `FiniteFieldDiffieHellman`: classic Diffie-Hellman with `BigInteger`, the math behind the key exchange |

`TlsEngine` is "sans I/O": bytes go in through `Receive` and records come out of
`TakeOutput`. That is what lets the tests replay RFC 8448's recorded bytes and
compare the output byte for byte.

## Implemented

| Area | Behavior |
| --- | --- |
| Versions | TLS 1.3 and 1.2, negotiated through supported_versions (RFC 8446 4.2.1); the DOWNGRD marker is written and checked (4.1.3); TLS_FALLBACK_SCSV is honored (RFC 7507) |
| TLS 1.3 suites | TLS_AES_128_GCM_SHA256 (preferred), TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| TLS 1.2 suites | ECDHE_ECDSA and ECDHE_RSA with AES_128_GCM_SHA256 or AES_256_GCM_SHA384 (RFC 5289); SHA-256/384 PRF |
| Key exchange | ephemeral ECDH on secp256r1 (default), secp384r1 and secp521r1; HelloRetryRequest both ways, cookie echo, message_hash transcript |
| Authentication | ECDSA and RSA certificates; TLS 1.3 signs with ECDSA or RSA-PSS, TLS 1.2 also with PKCS#1 v1.5; the client checks chain and host name by default |
| TLS 1.2 security | extended master secret (RFC 7627), secure renegotiation indication (RFC 5746); renegotiation is refused with a no_renegotiation warning |
| Records | per-record AEAD nonces (TLS 1.3 IV XOR sequence number; TLS 1.2 salt plus explicit nonce), 2^14 fragments, record_size_limit (RFC 8449) |
| Handshake rules | coalesced and fragmented messages; no message spanning a key change; middlebox compatibility mode (RFC 8446 D.4) |
| Post-handshake | TLS 1.3 KeyUpdate in both directions; NewSessionTicket ignored; an empty Certificate when a server asks for a client certificate |
| Alerts and closure | fatal alerts for protocol errors (encrypted once keys exist); close_notify with TLS 1.3 half-close; truncation detection |
| ALPN | server preference, `no_application_protocol` on mismatch (RFC 7301), ready for "h2" |

## Verification

`tests/TCP.Tests` (`TlsTests*.cs`):

- **RFC 8448 byte for byte.** Section 3 (simple 1-RTT) checks every secret, key,
  IV, transcript hash and Finished value. It re-encrypts every record of the
  trace, and replays whole flights through `TlsEngine`: the server answers the
  trace's ClientHello with the trace's exact ServerHello and encrypted flight;
  the client writes the trace's exact Finished, data and close_notify records.
  Section 5 checks P-256 ECDHE with the trace's keys and the HelloRetryRequest
  `message_hash` transcript. The trace bytes in `Rfc8448.cs` were extracted from
  the RFC text by a script that checks each length against the octet count the
  RFC prints beside it.
- **Our client against our server** over the in-memory TCP network. Covered:
  every suite and both certificate types, HelloRetryRequest, version
  negotiation, downgrade detection, ALPN mismatch, certificate rejection,
  tampering (bad_record_mac), a megabyte each way at a 600-byte MTU, KeyUpdate,
  truncation.
- **SslStream interop** through `TcpConnectionStream`, a thread-safe Stream over
  `TcpConnection`. On macOS: the SecureTransport TLS 1.2 client and server, and
  the Network.framework TLS 1.3 client. That client offers only an x25519 key
  share, so it exercises HelloRetryRequest. macOS cannot run a TLS 1.3 SslStream
  server, so that case is skipped there.
- **OpenSSL interop** (optional, when OpenSSL 3 is installed): our client against
  `openssl s_server` for TLS 1.3 and 1.2, bridged from the in-memory stack to a
  loopback socket.

## Not implemented

- Pre-shared keys, session resumption and 0-RTT. Tickets are received and ignored.
- Client certificates: the client can only decline, with an empty Certificate.
- X25519/X448: .NET 10 has no X25519 on macOS. The `TlsNamedGroup` values exist
  so offers are recognized; the server answers with a HelloRetryRequest for
  secp256r1.
- Finite-field (ffdhe) groups in the handshake (only the `Demos` class), EdDSA, and CBC or other legacy suites.
- OCSP stapling, certificate transparency, revocation checking, record padding,
  the exporter interface, and a handshake timeout.
