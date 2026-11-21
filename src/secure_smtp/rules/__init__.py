"""
Declarative Cryptographic Weakness Rule Engine Package.

Evaluates sessions, handshakes, and certificate chains against configurable YAML rules
for downgrade attacks, obsolete ciphers, expired certificates, and missing forward secrecy.
"""

from __future__ import annotations

from secure_smtp.rules.engine import RuleEngine

__all__ = ["RuleEngine"]
