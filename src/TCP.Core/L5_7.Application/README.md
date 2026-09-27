# L5–7 — Application

Namespace `TCP.L5_7.Application`. Layer 5 in the TCP/IP model; OSI layers 5–7
(session, presentation, application). Protocols that run over `L4.Transport`.

- `Http2` (`TCP.L5_7.Application.Http2`): an HTTP/2 frame decoder (RFC 9113 frame header,
  the ten frame types, per-type size and stream rules, the client connection preface).
  It labels and checks captured bytes; it is not an HTTP/2 server. Kestrel serves HTTP/2.
  HPACK (RFC 7541) header blocks stay opaque.
- `Tls` (`TCP.L5_7.Application.Tls`): TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246, ECDHE per
  RFC 8422, extended master secret per RFC 7627), client and server, over `TcpConnection`.
  ALPN can negotiate "h2". Verified byte for byte against RFC 8448 and interoperating with
  SslStream and OpenSSL. See [Tls/README.md](Tls/README.md).
