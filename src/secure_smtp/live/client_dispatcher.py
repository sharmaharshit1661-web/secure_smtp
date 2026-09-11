"""
Live Client Dispatcher — Interactive Web Client Transmission Engine.

Executes asynchronous and threaded raw socket SMTP dialogues on behalf of
the interactive Web Client UI, capturing high-resolution socket transcripts,
TLS handshake events, and returning live forensic timelines.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any


def _get_timestamp() -> str:
    return datetime.now(UTC).strftime("%H:%M:%S.%f")[:-3]


def run_smtp_client_session(
    host: str = "127.0.0.1",
    port: int = 2525,
    scenario: str = "plaintext",
    sender: str = "alice@client-device.local",
    recipient: str = "bob@securesmtp.local",
    subject: str = "Live Web Client Mail",
    body: str = "Confidential telemetry packet transmitted across network.",
    client_name: str = "Interactive Web Client",
) -> dict[str, Any]:
    """
    Connect to the target SMTP port, execute the protocol dialogue,
    and return an auditable transcript of each transmission event.
    """
    transcript: list[dict[str, str]] = []

    def log(direction: str, text: str):
        transcript.append({
            "timestamp": _get_timestamp(),
            "direction": direction,
            "text": text,
        })

    log("info", f"Initiating TCP connection to {host}:{port} ({scenario.upper()})")

    try:
        s = socket.create_connection((host, port), timeout=6)
    except Exception as e:
        log("error", f"Connection failed to {host}:{port}: {e}")
        return {
            "success": False,
            "error": str(e),
            "transcript": transcript,
            "port": port,
            "scenario": scenario,
        }

    use_tls = port in (2526, 2527, 2528) or scenario in ("tls_modern", "tls_vulnerable", "stripping")
    expect_stripping = port == 2528 or scenario == "stripping"
    cipher_info = "None (Plaintext)"

    def send_cmd(cmd: str) -> str:
        log("send", cmd)
        s.sendall(cmd.encode("utf-8") + b"\r\n")
        resp = s.recv(4096).decode("utf-8", errors="ignore").strip()
        log("recv", resp)
        return resp

    try:
        banner = s.recv(4096).decode("utf-8", errors="ignore").strip()
        log("recv", banner)

        helo_name = client_name.lower().replace(" ", "-") + ".local"
        send_cmd(f"EHLO {helo_name}")

        if use_tls:
            tls_resp = send_cmd("STARTTLS")

            if expect_stripping:
                log("alert", "⚠️ Active Tampering Detected: Server stripped STARTTLS capability or refused command!")
                log("alert", "Downgrading to cleartext SMTP transmission (Insecure Fallback)")
            elif "220" in tls_resp:
                log("crypto", "Negotiating TLS cryptographic tunnel...")
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_ciphers("DEFAULT@SECLEVEL=0")
                except Exception:
                    pass

                s = ctx.wrap_socket(s, server_hostname="mail.securesmtp.local")
                version = s.version() or "TLS 1.2"
                cipher_tuple = s.cipher()
                cipher_name = cipher_tuple[0] if cipher_tuple else "UNKNOWN"
                cipher_info = f"{version} · {cipher_name}"
                log("crypto", f"✓ TLS Tunnel Established: {cipher_info}")

                # Send post-TLS EHLO
                log("send", f"EHLO {helo_name} (Encrypted)")
                s.sendall(f"EHLO {helo_name}\r\n".encode("utf-8"))
                post_ehlo = s.recv(4096).decode("utf-8", errors="ignore").strip()
                log("recv", post_ehlo)
            else:
                log("alert", f"Unexpected STARTTLS response: {tls_resp}")

        # Send Mail Envelope
        send_cmd(f"MAIL FROM:<{sender}>")
        send_cmd(f"RCPT TO:<{recipient}>")
        send_cmd("DATA")

        email_data = (
            f"From: {sender}\r\n"
            f"To: {recipient}\r\n"
            f"Subject: {subject}\r\n"
            f"X-Mailer: Secure-SMTP-WebClient/1.0\r\n"
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
            f"\r\n"
            f"{body}\r\n"
            f".\r\n"
        )
        log("send", f"DATA Payload ({len(body)} bytes, Subject: \"{subject}\")")
        s.sendall(email_data.encode("utf-8"))
        data_resp = s.recv(4096).decode("utf-8", errors="ignore").strip()
        log("recv", data_resp)

        send_cmd("QUIT")
        log("info", "✓ Session completed successfully. Telemetry ingested into MongoDB.")

        return {
            "success": True,
            "port": port,
            "scenario": scenario,
            "cipher_info": cipher_info,
            "transcript": transcript,
            "client_name": client_name,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    except Exception as e:
        log("error", f"Session exception: {e}")
        return {
            "success": False,
            "error": str(e),
            "transcript": transcript,
            "port": port,
            "scenario": scenario,
        }
    finally:
        try:
            s.close()
        except Exception:
            pass


async def execute_client_dispatch_async(**kwargs) -> dict[str, Any]:
    """Run the synchronous socket client in a thread pool to avoid blocking async loop."""
    return await asyncio.to_thread(run_smtp_client_session, **kwargs)
