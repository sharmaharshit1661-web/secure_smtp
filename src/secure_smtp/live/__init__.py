"""
Live Mail Lab & Real-Time Traffic Simulator Package.

Runs an in-process multi-port mail lab (ports 2525-2528) supporting cleartext, modern TLS,
vulnerable ciphers, and STARTTLS stripping proxies with real-time socket packet inspection.
"""

from __future__ import annotations

from secure_smtp.live.client_dispatcher import execute_client_dispatch_async
from secure_smtp.live.generator import simulate_live_session
from secure_smtp.live.mail_server import LiveMailLab, get_live_lab, get_local_ip

__all__ = [
    "LiveMailLab",
    "get_live_lab",
    "get_local_ip",
    "simulate_live_session",
    "execute_client_dispatch_async",
]
