"""
Secure Mail Scope — Backward Compatibility Bridge.

This module provides compatibility re-exports for environments or scripts
referencing the earlier 'securemailscope' namespace. All active development
and primary implementations reside in 'secure_smtp'.
"""

from secure_smtp.config import Settings, get_settings

__all__ = ["Settings", "get_settings"]
