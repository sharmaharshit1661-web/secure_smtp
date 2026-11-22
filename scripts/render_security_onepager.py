"""Render the dated, one-page security audit and final build plan."""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output/pdf/Secure_SMTP_Final_Build_Plan_and_Audit.pdf"
NAVY = colors.HexColor("#172b3a")
TEAL = colors.HexColor("#09675e")
MUTED = colors.HexColor("#536472")
LIGHT = colors.HexColor("#eff4f6")
BODY = ParagraphStyle("Body", fontName="Helvetica", fontSize=9.5, leading=13,
                      textColor=NAVY, spaceAfter=5)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=8, leading=10.5,
                       textColor=MUTED)
HEADING = ParagraphStyle("Section", parent=BODY, fontName="Helvetica-Bold",
                         fontSize=11, leading=14, spaceBefore=10, spaceAfter=6)


def paragraph(text, style=BODY):
    return Paragraph(text, style)


def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(str(OUTPUT), pagesize=A4, leftMargin=36, rightMargin=36,
                                 topMargin=32, bottomMargin=32,
                                 title="Secure SMTP | Final build plan and security audit",
                                 author="Secure SMTP project")
    width = A4[0] - 72
    story = [
        paragraph("SECURE SMTP / RELEASE REVIEW", SMALL),
        paragraph("Final build plan &amp; product audit", ParagraphStyle(
            "Title", parent=BODY, fontName="Helvetica-Bold", fontSize=23, leading=27,
            spaceAfter=8)),
        paragraph("22 November 2026  |  Single-organization pilot  |  Online or offline installation", SMALL),
    ]
    verdict = Table([[paragraph("<b>LOCAL CHECKS PASS. DEPLOYMENT APPROVAL IS PENDING.</b><br/>"
        "Fixes are verified locally. Live identity, containers, browser flows and authorized traffic still need acceptance.")]], colWidths=[width])
    verdict.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([Spacer(1, 9), verdict, paragraph("Verified results", HEADING)])
    results = [
        ["Backend", "348 tests passed; 2 opt-in lab tests skipped"],
        ["Frontend", "22 tests passed; lint and both identity builds pass"],
        ["Dependencies", "0 known advisories: 92 Python packages, 132 npm dependencies*"],
        ["Runtime rehearsal", "Ingestion, scoped PDF, signed local alert, restart and restore pass"],
        ["Database permissions", "Application CRUD passes; foreign database/user administration denied"],
    ]
    table = Table([[paragraph(a), paragraph(b)] for a, b in results],
                  colWidths=[116, width - 116])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), .4, colors.HexColor("#dce4e8")),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.extend([table, Spacer(1, 5), paragraph(
        "*Two local Python projects are outside the PyPI scan. Container OS/image scanning is pending. "
        "Passing tests and advisory scans are not an independent security certification.", SMALL)])
    story.append(paragraph("What was corrected", HEADING))
    for text in [
        "<b>Access:</b> separate MongoDB application/root accounts; malformed Keycloak roles fail closed; offline WebSockets use the local allowed origin; router waits for local identity initialization.",
        "<b>Resilience:</b> API body limits and bounded Copilot queries; completed agent retries repair publication; failed/slow live sockets are pruned. Eight vulnerable Python packages were upgraded.",
        "<b>Evidence accuracy:</b> controlled-lab TLS failures remain incomplete; unmeasured fingerprints, key exchange and forward secrecy remain unknown. Backend and frontend lint checks pass.",
    ]:
        story.append(paragraph(text))
    story.append(paragraph("Final build plan - four release gates", HEADING))
    for text in [
        "<b>1. Freeze &amp; reproduce.</b> Review changes, create a clean dependency environment, rerun tests/scans, then build and scan target images and record their digests. Docker was unavailable here.",
        "<b>2. Configure.</b> Choose Clerk or local Keycloak; set verified users/roles, distinct secrets, DNS, trusted HTTPS, private databases and ingress abuse limits. Rotate old credentials. Existing volumes require an explicit account migration.",
        "<b>3. Rehearse.</b> Sign in, connect an authorized collector, generate mail traffic, inspect findings and export a scoped report. Test denied access, disconnect/replay, revocation, restart and backup restore; verify desktop/mobile controls and enabled integrations.",
        "<b>4. Approve the pilot.</b> Close the selected P0 acceptance gates before rollout. Keep one backend worker/instance and the lab disabled. Assign an operator and document recovery and known limits.",
    ]:
        story.append(paragraph(text))
    story.append(paragraph("Still open", HEADING))
    story.append(paragraph(
        "Real Clerk/Keycloak and browser acceptance; Docker/offline installation; authorized SMTP/IMAP/POP3 traffic; "
        "live Neo4j and intended alert receiver; load/rate-limit testing. Broader rollout also needs independent review, "
        "managed agents, durable workers, HA/DR and privacy approval. No government/defence certification is claimed.", BODY))
    story.extend([Spacer(1, 7), paragraph(
        "Evidence and detailed findings: docs/pilot/SECURITY_AUDIT.md and docs/pilot/evidence/. "
        "Local checks ran on macOS/Python 3.14; the target backend image uses Linux/Python 3.11.", SMALL)])

    def footer(canvas, doc):
        canvas.setStrokeColor(TEAL)
        canvas.setLineWidth(.8)
        canvas.line(36, 25, A4[0] - 36, 25)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(36, 15, "Secure SMTP | Engineering and SOC review | 22 Nov 2026")
        canvas.drawRightString(A4[0] - 36, 15, str(doc.page))

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUTPUT)


if __name__ == "__main__":
    build()
