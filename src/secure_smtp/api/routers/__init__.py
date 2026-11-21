"""
API Routers Package.

Organizes FastAPI route endpoints by domain:
- system: Health checks and client downloads
- analysis: PCAP upload and execution status
- hosts: Host inventory and posture summaries
- sessions: Session forensics and SHAP explainability
- reports: JSON, HTML, PDF export endpoints
- compliance: NIST, PCI-DSS, HIPAA, MTA-STS evaluations
- copilot: Generative AI incident briefings, Q&A, and mail daemon configs
- live: Live mail lab controls, attack simulations, and WebSocket streaming
"""

from __future__ import annotations

from secure_smtp.api.routers.analysis import router as analysis_router
from secure_smtp.api.routers.compliance import router as compliance_router
from secure_smtp.api.routers.copilot import router as copilot_router
from secure_smtp.api.routers.hosts import router as hosts_router
from secure_smtp.api.routers.live import router as live_router
from secure_smtp.api.routers.reports import router as reports_router
from secure_smtp.api.routers.sessions import router as sessions_router
from secure_smtp.api.routers.system import router as system_router

__all__ = [
    "system_router",
    "analysis_router",
    "hosts_router",
    "sessions_router",
    "reports_router",
    "compliance_router",
    "copilot_router",
    "live_router",
]
