"""
HTML report exporter using Jinja2 templates.
"""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import BaseLoader, Environment

logger = logging.getLogger(__name__)

# Inline HTML template — avoids template file dependency issues
REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure SMTP — Security Assessment Report</title>
    <style>
        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-card: #1a2235;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-cyan: #06b6d4;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #64748b;
            --border: #1e293b;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        h1 {
            font-size: 2rem;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        h2 {
            font-size: 1.4rem;
            color: var(--accent-cyan);
            margin: 2rem 0 1rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }

        h3 { font-size: 1.1rem; color: var(--text-primary); margin: 1rem 0 0.5rem; }

        .meta { color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 2rem; }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin: 1rem 0 2rem;
        }

        .stat-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.2rem;
            border: 1px solid var(--border);
        }

        .stat-card .label { font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }
        .stat-card .value { font-size: 1.8rem; font-weight: 700; margin-top: 0.3rem; }
        .stat-card .value.critical { color: var(--critical); }
        .stat-card .value.high { color: var(--high); }
        .stat-card .value.medium { color: var(--medium); }
        .stat-card .value.low { color: var(--low); }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            margin: 1rem 0;
        }

        th {
            background: var(--bg-secondary);
            color: var(--accent-cyan);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            padding: 0.8rem 1rem;
            text-align: left;
        }

        td {
            padding: 0.7rem 1rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }

        tr:last-child td { border-bottom: none; }
        tr:hover { background: rgba(59, 130, 246, 0.05); }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); }
        .badge.high { background: rgba(249, 115, 22, 0.2); color: var(--high); }
        .badge.medium { background: rgba(234, 179, 8, 0.2); color: var(--medium); }
        .badge.low { background: rgba(34, 197, 94, 0.2); color: var(--low); }
        .badge.info { background: rgba(100, 116, 139, 0.2); color: var(--info); }

        .session-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
        }

        .session-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .risk-score {
            font-size: 1.5rem;
            font-weight: 700;
            width: 60px;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            border: 3px solid;
        }

        .risk-score.critical { border-color: var(--critical); color: var(--critical); }
        .risk-score.high { border-color: var(--high); color: var(--high); }
        .risk-score.medium { border-color: var(--medium); color: var(--medium); }
        .risk-score.low { border-color: var(--low); color: var(--low); }

        .finding-item {
            padding: 0.8rem;
            margin: 0.5rem 0;
            border-left: 3px solid var(--border);
            background: var(--bg-secondary);
            border-radius: 0 8px 8px 0;
        }

        .finding-item.critical { border-left-color: var(--critical); }
        .finding-item.high { border-left-color: var(--high); }
        .finding-item.medium { border-left-color: var(--medium); }
        .finding-item.low { border-left-color: var(--low); }

        .finding-msg { font-weight: 500; margin-bottom: 0.3rem; }
        .finding-rec { color: var(--text-secondary); font-size: 0.85rem; }

        .tls-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.8rem; }
        .detail-item .label { font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; }
        .detail-item .value { font-weight: 500; }

        .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-secondary); font-size: 0.8rem; text-align: center; }

        @media print {
            body { background: white; color: black; }
            .stat-card, .session-card, table { border: 1px solid #ccc; }
            th { background: #f0f0f0; color: #333; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Secure SMTP</h1>
        <p class="meta">Cryptographic Security Posture Assessment Report — Generated {{ data.generated_at }}</p>

        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="stat-card">
                <div class="label">Total Hosts</div>
                <div class="value">{{ data.summary.total_hosts }}</div>
            </div>
            <div class="stat-card">
                <div class="label">Total Sessions</div>
                <div class="value">{{ data.summary.total_sessions }}</div>
            </div>
            <div class="stat-card">
                <div class="label">Critical Findings</div>
                <div class="value critical">{{ data.summary.critical_findings }}</div>
            </div>
            <div class="stat-card">
                <div class="label">High Findings</div>
                <div class="value high">{{ data.summary.high_findings }}</div>
            </div>
            <div class="stat-card">
                <div class="label">Medium Findings</div>
                <div class="value medium">{{ data.summary.medium_findings }}</div>
            </div>
            <div class="stat-card">
                <div class="label">Low Findings</div>
                <div class="value low">{{ data.summary.low_findings }}</div>
            </div>
        </div>

        <h2>Host Overview</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Sessions</th>
                    <th>Risk Score</th>
                </tr>
            </thead>
            <tbody>
                {% for host in data.hosts %}
                <tr>
                    <td>{{ host.ip_or_hostname }}</td>
                    <td>{{ host.session_count }}</td>
                    <td>
                        {% set score = host.aggregate_risk_score %}
                        {% if score >= 75 %}<span class="badge critical">{{ score }}</span>
                        {% elif score >= 50 %}<span class="badge high">{{ score }}</span>
                        {% elif score >= 25 %}<span class="badge medium">{{ score }}</span>
                        {% else %}<span class="badge low">{{ score }}</span>{% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Session Details</h2>
        {% for session in data.sessions %}
        <div class="session-card">
            <div class="session-header">
                <div>
                    <h3>{{ session.src_ip }}:{{ session.src_port }} → {{ session.dst_ip }}:{{ session.dst_port }}</h3>
                    <span class="badge info">{{ session.protocol | upper }}</span>
                    <span class="badge {% if session.tls_mode == 'none' %}critical{% else %}low{% endif %}">
                        TLS: {{ session.tls_mode }}
                    </span>
                </div>
                {% if session.risk_score %}
                <div class="risk-score {{ session.risk_score.tier }}">
                    {{ session.risk_score.score | int }}
                </div>
                {% endif %}
            </div>

            {% if session.handshake %}
            <div class="tls-details">
                <div class="detail-item">
                    <div class="label">TLS Version</div>
                    <div class="value">{{ session.handshake.tls_version_negotiated }}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Cipher Suite</div>
                    <div class="value">{{ session.handshake.cipher_suite_negotiated }}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Key Exchange</div>
                    <div class="value">{{ session.handshake.key_exchange_type }}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Forward Secrecy</div>
                    <div class="value">{{ "✅ Yes" if session.handshake.forward_secrecy else "❌ No" }}</div>
                </div>
                {% if session.handshake.ja3 %}
                <div class="detail-item">
                    <div class="label">JA3</div>
                    <div class="value" style="font-size: 0.75rem;">{{ session.handshake.ja3 }}</div>
                </div>
                {% endif %}
            </div>
            {% endif %}

            {% if session.findings %}
            <h3 style="margin-top: 1rem;">Findings ({{ session.findings | length }})</h3>
            {% for finding in session.findings %}
            <div class="finding-item {{ finding.severity }}">
                <div style="margin-bottom: 0.3rem;">
                    <span class="badge {{ finding.severity }}">{{ finding.severity }}</span>
                    <strong>{{ finding.rule_id }}</strong>
                </div>
                <div class="finding-msg">{{ finding.message }}</div>
                <div class="finding-rec">💡 {{ finding.recommendation }}</div>
            </div>
            {% endfor %}
            {% endif %}
        </div>
        {% endfor %}

        <div class="footer">
            <p>Secure SMTP — Passive Cryptographic Posture Intelligence & Explainable AI Risk Attribution</p>
            <p>Project belongs to <a href="https://github.com/sharmaharshit1661-web" target="_blank" style="color: inherit; text-decoration: none;">@sharmaharshit1661-web</a> &bull; Findings should be validated by a security professional.</p>
        </div>
    </div>
</body>
</html>"""


def generate_html_report(report_data: dict, output_path: str) -> str:
    """
    Generate an HTML report from analysis data.

    Args:
        report_data: Complete report data structure.
        output_path: Path to write the HTML file.

    Returns:
        Path to the generated file.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(REPORT_TEMPLATE)
    html = template.render(data=report_data)

    with open(output, "w") as f:
        f.write(html)

    logger.info("Generated HTML report: %s", output)
    return str(output)
