"""Convert local TCP streams to a strict metadata allowlist; discard raw payloads."""
import re
from datetime import UTC, datetime
from uuid import uuid4

from secure_smtp.ingest.protocol_id import identify_protocol
from secure_smtp.ingest.tcp_stream import reassemble_stream
from secure_smtp.monitoring.schema import CertificateMetadata, HandshakeMetadata, Observation
from secure_smtp.tls.cert_parser import parse_certificate_chain
from secure_smtp.tls.fingerprint import compute_fingerprints
from secure_smtp.tls.handshake_parser import parse_handshake

PLAIN = re.compile(rb'(?im)^(?:220[ -]|250[ -]|EHLO |HELO |MAIL FROM:|RCPT TO:|STARTTLS\r?$|\+OK |\* OK |\w+ (?:CAPABILITY|LOGIN|STARTTLS)\b|USER |PASS |STLS\r?$)')


def observe_stream(stream, complete=False):
    transport = reassemble_stream(stream)
    proto = identify_protocol(transport)
    if proto.protocol.value not in ('smtp', 'imap', 'pop3'):
        return None
    c2s, s2c = transport.client_to_server.data, transport.server_to_client.data
    mode = proto.tls_mode.value
    if mode == 'none' and not PLAIN.search(c2s + b'\n' + s2c):
        mode = 'unknown'
    handshake, certificates = None, []
    if mode in ('implicit', 'starttls'):
        parsed = parse_handshake(c2s, s2c, proto.tls_offset_client, proto.tls_offset_server)
        fingerprints = compute_fingerprints(parsed.client_hello, parsed.server_hello)
        handshake = HandshakeMetadata(tls_version_negotiated=parsed.tls_version_negotiated or '',
            cipher_suite_negotiated=parsed.cipher_suite_negotiated or '',
            key_exchange_type=parsed.key_exchange_type.value,
            forward_secrecy=parsed.forward_secrecy if parsed.server_hello else None,
            visibility_limited=parsed.visibility_limited,
            ja3=fingerprints.ja3 or '', ja3s=fingerprints.ja3s or '')
        for cert in parse_certificate_chain(parsed.raw_certificates[:10]):
            certificates.append(CertificateMetadata(chain_position=cert.chain_position,
                not_before=cert.not_before, not_after=cert.not_after,
                public_key_algorithm=cert.public_key_algorithm if cert.public_key_algorithm in ('RSA','EC','ECDSA','DSA','Ed25519','Ed448') else 'unknown',
                key_length_bits=cert.key_length_bits, signature_algorithm=cert.signature_algorithm[:160],
                self_signed=cert.self_signed))
    return Observation(event_id=uuid4(), observed_at=datetime.fromtimestamp(max(p.timestamp for p in stream.packets), UTC),
        src_ip=transport.client_ip, dst_ip=transport.server_ip, src_port=transport.client_port, dst_port=transport.server_port,
        protocol=proto.protocol.value, tls_mode=mode, starttls_advertised=proto.starttls_advertised,
        starttls_completed=proto.starttls_completed, capture_complete=complete, handshake=handshake, certificates=certificates)
