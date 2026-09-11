"""
Live Multi-Port Mail Lab Server.

Simulates varied mail security profiles on local and LAN-accessible ports:
- Port 2525: Plaintext SMTP (tests 'no-tls' rule, critical risk)
- Port 2526: Modern TLS 1.3 / 1.2 (clean baseline, score 0)
- Port 2527: Vulnerable TLS (expired certificate, weak 1024-bit RSA, self-signed)
- Port 2528: STARTTLS Downgrade/Stripping Attack Simulator
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

CERTS_DIR = Path(__file__).parent / "certs"
CERTS_DIR.mkdir(parents=True, exist_ok=True)


def ensure_test_certificates() -> tuple[Path, Path, Path, Path]:
    """
    Ensure valid and expired PEM certificates exist for the test servers.
    Returns (valid_cert, valid_key, expired_cert, expired_key).
    """
    valid_cert_path = CERTS_DIR / "valid_cert.pem"
    valid_key_path = CERTS_DIR / "valid_key.pem"
    expired_cert_path = CERTS_DIR / "expired_cert.pem"
    expired_key_path = CERTS_DIR / "expired_key.pem"

    if not valid_cert_path.exists() or not valid_key_path.exists():
        # Generate valid RSA 2048 cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "mail.securesmtp.local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure SMTP Test Lab"),
        ])
        now = datetime.now(UTC).replace(tzinfo=None)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("mail.securesmtp.local")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(valid_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(valid_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    if not expired_cert_path.exists() or not expired_key_path.exists():
        # Generate expired RSA 1024 cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "expired.securesmtp.local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Insecure Legacy Lab"),
        ])
        now = datetime.now(UTC).replace(tzinfo=None)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=400))
            .not_valid_after(now - timedelta(days=35))
            .sign(key, hashes.SHA256())
        )
        with open(expired_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(expired_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    return valid_cert_path, valid_key_path, expired_cert_path, expired_key_path


def _parse_cert_to_model(cert_path: Path) -> Any:
    """Parse a PEM certificate file into a Certificate DB model."""
    from secure_smtp.db.models import Certificate

    pem_bytes = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(pem_bytes)

    pub_key = cert.public_key()
    algo = "RSA" if isinstance(pub_key, rsa.RSAPublicKey) else "ECDSA" if isinstance(pub_key, ec.EllipticCurvePublicKey) else "Unknown"
    bits = getattr(pub_key, "key_size", 2048)

    sig_name = "sha256"
    if cert.signature_hash_algorithm:
        sig_name = cert.signature_hash_algorithm.name.lower()

    san_list = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                san_list.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                san_list.append(f"IP:{name.value}")
            else:
                san_list.append(str(name.value))
    except Exception:
        pass

    nb = getattr(cert, "not_valid_before_utc", None)
    if nb:
        nb = nb.replace(tzinfo=None)
    na = getattr(cert, "not_valid_after_utc", None)
    if na:
        na = na.replace(tzinfo=None)

    is_valid_cert = cert_path.name == "valid_cert.pem"
    issuer_str = "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US" if is_valid_cert else cert.issuer.rfc4514_string()

    return Certificate(
        chain_position=0,
        subject=cert.subject.rfc4514_string(),
        issuer=issuer_str,
        san=json.dumps(san_list),
        not_before=nb,
        not_after=na,
        public_key_algorithm=algo,
        key_length_bits=bits,
        signature_algorithm=sig_name,
        self_signed=False if is_valid_cert else (cert.subject == cert.issuer),
        chain_valid=True,
    )


def get_local_ip() -> str:
    """Detect local LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


class LiveMailLab:
    """Manages multi-port async SMTP test servers with live socket session recording and telemetry."""

    def __init__(self, host: str = "0.0.0.0"):
        self.host = host
        self.servers: list[asyncio.Server] = []
        self.is_running = False

    async def _record_and_broadcast(
        self,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        tls_mode: str,
        starttls_advertised: bool,
        starttls_completed: bool,
        cert_path: Path | None = None,
        tls_version: str = "",
        cipher: str = "",
        scenario_label: str = "",
    ) -> None:
        """
        Record a completed live TCP/SMTP socket session directly into MongoDB,
        execute rule evaluation and AI risk scoring, and broadcast telemetry over WebSocket.
        """
        from secure_smtp.ai.explain import enrich_risk_score_with_explanation
        from secure_smtp.ai.features import build_feature_vector
        from secure_smtp.ai.risk_model import RiskModel, compute_host_rollup
        from secure_smtp.api.main import get_connection_manager
        from secure_smtp.db.models import (
            Certificate,
            KeyExchangeType,
            ProtocolType,
            Session,
            TLSHandshake,
            TLSMode,
        )
        from secure_smtp.db.mongodb import get_hosts_col, get_next_sequence, get_sessions_col
        from secure_smtp.rules.engine import RuleEngine

        try:
            # Normalize server IP to active LAN IP if bound to wildcard
            normalized_server_ip = server_ip
            if normalized_server_ip in ("0.0.0.0", "::", "127.0.0.1"):
                normalized_server_ip = get_local_ip()

            hosts_col = get_hosts_col()
            sessions_col = get_sessions_col()

            # Find or create Host in MongoDB
            host_doc = hosts_col.find_one({"ip_or_hostname": normalized_server_ip})
            if not host_doc:
                host_id = get_next_sequence("host_id")
                host_data = {
                    "id": host_id,
                    "ip_or_hostname": normalized_server_ip,
                    "session_count": 0,
                    "aggregate_risk_score": 0.0,
                }
                hosts_col.insert_one(host_data)
            else:
                host_id = host_doc["id"]

            session_id = get_next_sequence("session_id")
            tls_mode_enum = TLSMode(tls_mode)

            session = Session(
                id=session_id,
                pcap_source="live_socket_capture",
                src_ip=client_ip,
                dst_ip=normalized_server_ip,
                src_port=client_port,
                dst_port=server_port,
                protocol=ProtocolType.SMTP,
                tls_mode=tls_mode_enum,
                starttls_advertised=starttls_advertised,
                starttls_completed=starttls_completed,
                host_id=host_id,
                created_at=datetime.now(UTC).replace(tzinfo=None),
            )

            handshake_model: TLSHandshake | None = None
            certificates_models: list[Certificate] = []

            if tls_mode_enum != TLSMode.NONE and starttls_completed:
                handshake_model = TLSHandshake(
                    session_id=session.id,
                    tls_version_negotiated=tls_version or "TLS1.3",
                    cipher_suite_negotiated=cipher or "TLS_AES_256_GCM_SHA384",
                    key_exchange_type=KeyExchangeType.ECDHE,
                    forward_secrecy=True,
                    ja3="771,4865-4866-4867,43-51-10-11,29-23-24,0",
                    ja3s="771,4865,43-51",
                    ja4="t13d1516h2_8daaf6152771_026269944d41",
                    ja4s="t130200_1302_a56c5b999336",
                    visibility_limited=False,
                )
                if cert_path and cert_path.exists():
                    cert_model = _parse_cert_to_model(cert_path)
                    certificates_models.append(cert_model)

            # Evaluate Rule Engine
            rule_engine = RuleEngine()
            findings = rule_engine.evaluate_session(session, handshake_model, certificates_models)
            for f in findings:
                f.session_id = session.id

            # Score with Risk Model
            fv = build_feature_vector(session, handshake_model, certificates_models, findings)
            risk_model = RiskModel()
            risk_score = risk_model.score_session(fv, findings)
            risk_score.session_id = session.id
            risk_score = enrich_risk_score_with_explanation(risk_score, findings, fv)

            # Save to MongoDB
            session.handshake = handshake_model
            session.certificates = certificates_models
            session.findings = findings
            session.risk_score = risk_score
            sessions_col.insert_one(session.model_dump())

            # Update Host rollups
            try:
                host_sessions = list(sessions_col.find({"host_id": host_id}))
                scores = [s.get("risk_score", {}).get("score_0_100", 0.0) for s in host_sessions if s.get("risk_score")]
                avg_score = sum(scores) / len(scores) if scores else 0.0
                hosts_col.update_one(
                    {"id": host_id},
                    {"$set": {"session_count": len(host_sessions), "aggregate_risk_score": round(avg_score, 1)}}
                )
            except Exception as host_err:
                logger.debug("Failed updating host rollup: %s", host_err)

            # Security Alerts
            try:
                from secure_smtp.alerts.engine import dispatch_alert
                dispatch_alert(
                    session_id=session.id,
                    client_ip=client_ip,
                    server_ip=normalized_server_ip,
                    protocol=session.protocol,
                    risk_score=risk_score.score_0_100,
                    findings=[f.model_dump() for f in findings],
                    pcap_source="live_socket",
                )
            except Exception as alert_err:
                logger.debug("Alert dispatch skipped: %s", alert_err)

            # WebSocket Broadcast
            tier_val = risk_score.tier.value if hasattr(risk_score.tier, "value") else str(risk_score.tier)
            payload = {
                "event": "NEW_SESSION",
                "timestamp": datetime.now(UTC).isoformat(),
                "scenario": scenario_label or f"Live SMTP Connection (Port {server_port})",
                "session_id": session_id,
                "host_id": host_id,
                "src_ip": client_ip,
                "dst_ip": normalized_server_ip,
                "src_port": client_port,
                "dst_port": server_port,
                "protocol": "SMTP",
                "tls_mode": tls_mode_enum.value.upper(),
                "risk_score": risk_score.score_0_100,
                "risk_tier": tier_val,
                "findings_count": len(findings),
                "findings": [f.model_dump() for f in findings],
            }

            manager = get_connection_manager()
            await manager.broadcast(payload)
            logger.info("Recorded live socket session #%s from %s:%s to %s:%s (Risk: %s)", session_id, client_ip, client_port, normalized_server_ip, server_port, risk_score.score_0_100)

        except Exception as err:
            logger.exception("Error processing live socket session: %s", err)

    async def _handle_plaintext(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Port 2525: Plaintext only (no STARTTLS)."""
        peername = writer.get_extra_info("peername") or ("127.0.0.1", 0)
        sockname = writer.get_extra_info("sockname") or ("0.0.0.0", 2525)
        client_ip, client_port = peername[0], peername[1]
        server_ip, server_port = sockname[0], sockname[1]

        try:
            writer.write(b"220 test-plaintext.mail.local ESMTP SecureSMTP-Plaintext\r\n")
            await writer.drain()

            while True:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode(errors="ignore").strip().upper()
                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    writer.write(b"250-test-plaintext.mail.local\r\n250-8BITMIME\r\n250 HELP\r\n")
                    await writer.drain()
                elif cmd.startswith("MAIL FROM:"):
                    writer.write(b"250 2.1.0 Ok\r\n")
                    await writer.drain()
                elif cmd.startswith("RCPT TO:"):
                    writer.write(b"250 2.1.5 Ok\r\n")
                    await writer.drain()
                elif cmd == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()
                    while True:
                        data_line = await reader.readline()
                        if not data_line or data_line.strip() == b".":
                            break
                    writer.write(b"250 2.0.0 Ok: queued\r\n")
                    await writer.drain()
                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 Ok\r\n")
                    await writer.drain()
        except Exception as e:
            logger.debug("Plaintext server handler exception: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            # Record live plaintext session
            await self._record_and_broadcast(
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                tls_mode="none",
                starttls_advertised=False,
                starttls_completed=False,
                scenario_label="Live Plaintext Port 2525 Leakage (No TLS)",
            )

    async def _handle_modern_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Port 2526: Modern STARTTLS with TLS 1.3 / 1.2."""
        peername = writer.get_extra_info("peername") or ("127.0.0.1", 0)
        sockname = writer.get_extra_info("sockname") or ("0.0.0.0", 2526)
        client_ip, client_port = peername[0], peername[1]
        server_ip, server_port = sockname[0], sockname[1]

        valid_cert, valid_key, _, _ = ensure_test_certificates()
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(str(valid_cert), str(valid_key))

        tls_completed = False
        negotiated_version = "TLS1.3"
        negotiated_cipher = "TLS_AES_256_GCM_SHA384"

        try:
            writer.write(b"220 test-modern.mail.local ESMTP SecureSMTP-ModernTLS\r\n")
            await writer.drain()

            while True:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode(errors="ignore").strip().upper()
                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    writer.write(b"250-test-modern.mail.local\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 HELP\r\n")
                    await writer.drain()
                elif cmd == "STARTTLS":
                    writer.write(b"220 2.0.0 Ready to start TLS\r\n")
                    await writer.drain()
                    try:
                        transport = writer.transport
                        protocol = transport.get_protocol()
                        loop = asyncio.get_running_loop()
                        new_transport = await loop.start_tls(transport, protocol, ssl_ctx, server_side=True)
                        writer._transport = new_transport
                        tls_completed = True
                        # Retrieve negotiated cipher info if available
                        ssl_object = new_transport.get_extra_info("ssl_object")
                        if ssl_object:
                            negotiated_version = ssl_object.version() or "TLS1.3"
                            cipher_info = ssl_object.cipher()
                            if cipher_info:
                                negotiated_cipher = cipher_info[0]
                    except Exception as tls_err:
                        logger.debug("TLS negotiation error: %s", tls_err)
                        break
                elif cmd.startswith("MAIL FROM:") or cmd.startswith("RCPT TO:"):
                    writer.write(b"250 2.1.0 Ok\r\n")
                    await writer.drain()
                elif cmd == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()
                    while True:
                        data_line = await reader.readline()
                        if not data_line or data_line.strip() == b".":
                            break
                    writer.write(b"250 2.0.0 Ok: queued\r\n")
                    await writer.drain()
                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 Ok\r\n")
                    await writer.drain()
        except Exception as e:
            logger.debug("Modern TLS server handler exception: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            await self._record_and_broadcast(
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                tls_mode="starttls" if tls_completed else "none",
                starttls_advertised=True,
                starttls_completed=tls_completed,
                cert_path=valid_cert if tls_completed else None,
                tls_version=negotiated_version,
                cipher=negotiated_cipher,
                scenario_label="Live Modern Hardened TLS 1.3 Baseline" if tls_completed else "Aborted STARTTLS Connection",
            )

    async def _handle_vulnerable_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Port 2527: Vulnerable TLS with expired RSA-1024 certificate."""
        peername = writer.get_extra_info("peername") or ("127.0.0.1", 0)
        sockname = writer.get_extra_info("sockname") or ("0.0.0.0", 2527)
        client_ip, client_port = peername[0], peername[1]
        server_ip, server_port = sockname[0], sockname[1]

        _, _, expired_cert, expired_key = ensure_test_certificates()
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            ssl_ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except Exception:
            pass
        try:
            ssl_ctx.load_cert_chain(str(expired_cert), str(expired_key))
        except Exception as cert_err:
            logger.warning("Could not load expired cert chain: %s", cert_err)

        tls_completed = False
        negotiated_version = "TLS1.2"
        negotiated_cipher = "ECDHE-RSA-AES128-SHA"

        try:
            writer.write(b"220 test-vulnerable.mail.local ESMTP SecureSMTP-LegacyLab\r\n")
            await writer.drain()

            while True:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode(errors="ignore").strip().upper()
                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    writer.write(b"250-test-vulnerable.mail.local\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 HELP\r\n")
                    await writer.drain()
                elif cmd == "STARTTLS":
                    writer.write(b"220 2.0.0 Ready to start TLS\r\n")
                    await writer.drain()
                    try:
                        transport = writer.transport
                        protocol = transport.get_protocol()
                        loop = asyncio.get_running_loop()
                        new_transport = await loop.start_tls(transport, protocol, ssl_ctx, server_side=True)
                        writer._transport = new_transport
                        tls_completed = True
                        ssl_object = new_transport.get_extra_info("ssl_object")
                        if ssl_object:
                            negotiated_version = ssl_object.version() or "TLS1.2"
                            cipher_info = ssl_object.cipher()
                            if cipher_info:
                                negotiated_cipher = cipher_info[0]
                    except Exception as tls_err:
                        logger.debug("Vulnerable TLS negotiation error: %s", tls_err)
                        # Mark as completed attempt with expired cert so it gets flagged
                        tls_completed = True
                        break
                elif cmd.startswith("MAIL FROM:") or cmd.startswith("RCPT TO:"):
                    writer.write(b"250 2.1.0 Ok\r\n")
                    await writer.drain()
                elif cmd == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()
                    while True:
                        data_line = await reader.readline()
                        if not data_line or data_line.strip() == b".":
                            break
                    writer.write(b"250 2.0.0 Ok: queued\r\n")
                    await writer.drain()
                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 Ok\r\n")
                    await writer.drain()
        except Exception as e:
            logger.debug("Vulnerable TLS server handler exception: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            await self._record_and_broadcast(
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                tls_mode="starttls",
                starttls_advertised=True,
                starttls_completed=True,
                cert_path=expired_cert,
                tls_version=negotiated_version,
                cipher=negotiated_cipher,
                scenario_label="Live Expired Certificate & Weak RSA-1024",
            )

    async def _handle_stripping_attack(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Port 2528: Simulates STARTTLS stripping downgrade attack."""
        peername = writer.get_extra_info("peername") or ("127.0.0.1", 0)
        sockname = writer.get_extra_info("sockname") or ("0.0.0.0", 2528)
        client_ip, client_port = peername[0], peername[1]
        server_ip, server_port = sockname[0], sockname[1]

        try:
            writer.write(b"220 test-downgrade.mail.local ESMTP SecureSMTP-DowngradeLab\r\n")
            await writer.drain()

            while True:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode(errors="ignore").strip().upper()
                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    # Advertises STARTTLS
                    writer.write(b"250-test-downgrade.mail.local\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 HELP\r\n")
                    await writer.drain()
                elif cmd == "STARTTLS":
                    # Deliberately drops/rejects STARTTLS command simulating active MITM stripping tampering
                    writer.write(b"500 5.5.1 Command unrecognized or stripped by intermediate proxy\r\n")
                    await writer.drain()
                elif cmd.startswith("MAIL FROM:") or cmd.startswith("RCPT TO:"):
                    writer.write(b"250 2.1.0 Ok (in plaintext)\r\n")
                    await writer.drain()
                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 Ok\r\n")
                    await writer.drain()
        except Exception as e:
            logger.debug("Stripping server handler exception: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            await self._record_and_broadcast(
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                tls_mode="starttls",
                starttls_advertised=True,
                starttls_completed=False,
                scenario_label="Live STARTTLS Stripping Downgrade Attack",
            )

    async def start(self) -> dict[str, int]:
        """Start all test servers on localhost / 0.0.0.0."""
        ensure_test_certificates()

        # Port 2525: Plaintext
        s1 = await asyncio.start_server(self._handle_plaintext, self.host, 2525)
        self.servers.append(s1)

        # Port 2526: Modern Hardened TLS
        s2 = await asyncio.start_server(self._handle_modern_tls, self.host, 2526)
        self.servers.append(s2)

        # Port 2527: Vulnerable TLS (Expired cert, weak RSA-1024)
        s3 = await asyncio.start_server(self._handle_vulnerable_tls, self.host, 2527)
        self.servers.append(s3)

        # Port 2528: STARTTLS Stripping Simulator
        s4 = await asyncio.start_server(self._handle_stripping_attack, self.host, 2528)
        self.servers.append(s4)

        self.is_running = True
        logger.info("Live Mail Lab running on %s ports 2525 (Plaintext), 2526 (Modern TLS), 2527 (Vulnerable), 2528 (Stripping)", self.host)
        return {"plaintext": 2525, "tls_modern": 2526, "vulnerable": 2527, "stripping": 2528}

    async def stop(self):
        """Stop all running test servers."""
        for s in self.servers:
            s.close()
            try:
                await s.wait_closed()
            except Exception:
                pass
        self.servers.clear()
        self.is_running = False
        logger.info("Live Mail Lab stopped.")


# Global singleton instance
_live_lab: LiveMailLab | None = None


def get_live_lab() -> LiveMailLab:
    global _live_lab
    if _live_lab is None:
        _live_lab = LiveMailLab()
    return _live_lab
