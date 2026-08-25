import sys
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (pages 2+)
        if self._pageNumber > 1:
            self.drawString(54, 750, "BankSec Core v1.0 — Architecture & Operational Guide")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)
            
        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)
        
        self.drawString(54, 32, "CONFIDENTIAL — FOR FINANCIAL & REGULATORY AUDIT USE ONLY")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.restoreState()

def build_pdf():
    pdf_filename = r"D:\crazy_projects\banksec-suite\BankSec_Core_Architecture_and_User_Guide.pdf"
    artifact_filename = r"C:\Users\user\.gemini\antigravity\brain\5fed4272-a0ad-49fa-b30d-aa7da3ab6d48\BankSec_Core_Architecture_and_User_Guide.pdf"
    
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=60,
        bottomMargin=60
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#10b981"),
        spaceAfter=15
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=13,
        textColor=colors.HexColor("#3b82f6"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12.5,
        textColor=colors.HexColor("#334155"),
        spaceAfter=6
    )
    
    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=body_style,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    tbl_header_style = ParagraphStyle(
        'TblHeader',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    tbl_cell_style = ParagraphStyle(
        'TblCell',
        fontName='Helvetica',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#1e293b")
    )
    
    tbl_cell_bold = ParagraphStyle(
        'TblCellBold',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#0f172a")
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#cbd5e1"),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )

    story = []

    # Title Banner
    story.append(Paragraph("🏛️ BankSec Core v1.0", title_style))
    story.append(Paragraph("TECHNICAL ARCHITECTURE, OPERATIONAL GUIDE & SCOPE SPECIFICATION", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceAfter=12))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary & Value Proposition", h1_style))
    story.append(Paragraph(
        "<b>BankSec Core</b> is an enterprise-grade Application Security & Regulatory Assurance Engine "
        "built specifically for core banking systems, fintech web applications, payment gateways, and Open Banking APIs. "
        "It evaluates financial software against international banking benchmarks including <b>OAuth2 FAPI 1.0/2.0</b>, "
        "<b>PCI-DSS v4.0</b>, <b>OWASP ASVS Level 3</b>, and <b>PSD2 RTS (Strong Customer Authentication)</b>.",
        body_style
    ))
    
    story.append(Paragraph("• <b>Financial-Grade Compliance</b>: Evaluates token binding (DPoP), anti-replay transaction locking, and strict header transport policies.", bullet_style))
    story.append(Paragraph("• <b>Executive & Auditor Visibility</b>: Translates technical probes into an interactive Audit Score (0-100%) and Grade (A+ to F).", bullet_style))
    story.append(Paragraph("• <b>Production Remediation</b>: Provides copy-pasteable remediation code in Express Node.js, Spring Boot Java, and Python.", bullet_style))
    story.append(Paragraph("• <b>Zero-Downtime Safe Probing</b>: Layer 7 non-destructive checks safe for live production banking endpoints.", bullet_style))
    story.append(Spacer(1, 8))

    # Use Cases
    story.append(Paragraph("2. Target Use Cases & Deployment Environments", h1_style))
    story.append(Paragraph("• <b>Pre-Audit Readiness Assessment</b>: Prepare web applications for RBI, SEBI, ISO 27001, and PCI-DSS v4.0 audits.", bullet_style))
    story.append(Paragraph("• <b>DevSecOps Integration</b>: Validate security header configurations in CI/CD staging pipelines before release.", bullet_style))
    story.append(Paragraph("• <b>Third-Party Fintech API Vetting</b>: Verify security postures of vendors and Open Banking partners prior to integration.", bullet_style))
    story.append(Spacer(1, 8))

    # System Architecture
    story.append(Paragraph("3. System Architecture", h1_style))
    story.append(Paragraph(
        "BankSec Core utilizes a decoupled dual-deployment architecture supporting both <b>Standalone Local Execution (Node.js/Express)</b> "
        "and <b>Cloud Serverless Deployment (Streamlit Community Cloud)</b>.",
        body_style
    ))
    
    arch_data = [
        [Paragraph("Component", tbl_header_style), Paragraph("Technology Stack", tbl_header_style), Paragraph("Function & Responsibilities", tbl_header_style)],
        [Paragraph("Frontend UI Engine", tbl_cell_bold), Paragraph("HTML5, Vanilla CSS3, JS / Streamlit", tbl_cell_style), Paragraph("Renders glassmorphism dashboard, metric dials, tabs, & modals.", tbl_cell_style)],
        [Paragraph("Probe Engine", tbl_cell_bold), Paragraph("Node.js HTTP/S & Python Requests", tbl_cell_style), Paragraph("Executes Layer 7 probes, TLS inspection, & header extraction.", tbl_cell_style)],
        [Paragraph("Audit Engine", tbl_cell_bold), Paragraph("JavaScript & Python Rule Engine", tbl_cell_style), Paragraph("Maps findings to controls, computes score (0-100%), & assigns Grade.", tbl_cell_style)],
        [Paragraph("Data Model", tbl_cell_bold), Paragraph("banking-framework.js / Python dict", tbl_cell_style), Paragraph("Defines 5 banking security domains, 11 controls, & OWASP matrices.", tbl_cell_style)]
    ]
    arch_table = Table(arch_data, colWidths=[110, 140, 254])
    arch_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")])
    ]))
    story.append(arch_table)
    story.append(Spacer(1, 10))

    # Scope Specification
    story.append(Paragraph("4. Scope Specification: What CAN & CANNOT Be Tested", h1_style))
    
    scope_data = [
        [Paragraph("Category", tbl_header_style), Paragraph("What CAN Be Tested (In-Scope)", tbl_header_style), Paragraph("What CANNOT Be Tested (Safety Boundary)", tbl_header_style)],
        [Paragraph("Transport Security", tbl_cell_bold), Paragraph("HTTPS / TLS 1.3 encryption & protocol enforcement.", tbl_cell_style), Paragraph("Network Layer 3/4 DDoS or raw port scanning.", tbl_cell_style)],
        [Paragraph("Security Headers", tbl_cell_bold), Paragraph("HSTS preloading, CSP, X-Frame-Options, X-Content-Type-Options.", tbl_cell_style), Paragraph("Deep business logic flaws (account balance manipulation).", tbl_cell_style)],
        [Paragraph("API & CORS Policy", tbl_cell_bold), Paragraph("Wildcard Access-Control-Allow-Origin (*) & Server Banner leakage.", tbl_cell_style), Paragraph("Heavy SQL Injection / payload fuzzing (to avoid WAF bans).", tbl_cell_style)],
        [Paragraph("Audit & Compliance", tbl_cell_bold), Paragraph("Automated mapping to 11 Banking Controls, OWASP, & FAPI.", tbl_cell_style), Paragraph("Authenticated exploits requiring stored user credentials/MFA.", tbl_cell_style)]
    ]
    scope_table = Table(scope_data, colWidths=[100, 204, 200])
    scope_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")])
    ]))
    story.append(scope_table)
    story.append(Spacer(1, 10))

    # Audit Engine & Scoring Methodology
    story.append(Paragraph("5. Audit Engine & Scoring Methodology", h1_style))
    story.append(Paragraph(
        "The Audit Engine evaluates financial application readiness using a transparent percentage formula:<br/>"
        "<b>Audit Compliance Score (%) = (Passed Controls / Total Controls) × 100</b>",
        body_style
    ))
    
    grade_data = [
        [Paragraph("Score Range", tbl_header_style), Paragraph("Compliance Grade", tbl_header_style), Paragraph("Financial Audit Status & Recommended Action", tbl_header_style)],
        [Paragraph("90% – 100%", tbl_cell_bold), Paragraph("<font color='#10b981'><b>GRADE A+</b></font>", tbl_cell_style), Paragraph("<b>Banking Compliant</b>: Meets FAPI 1.0/2.0, PCI-DSS v4.0, & ASVS Level 3.", tbl_cell_style)],
        [Paragraph("70% – 89%", tbl_cell_bold), Paragraph("<font color='#f59e0b'><b>GRADE B</b></font>", tbl_cell_style), Paragraph("<b>Moderate Risk</b>: Basic HTTPS active; secondary header fixes required before release.", tbl_cell_style)],
        [Paragraph("0% – 69%", tbl_cell_bold), Paragraph("<font color='#f43f5e'><b>GRADE F</b></font>", tbl_cell_style), Paragraph("<b>Critical Vulnerabilities</b>: Essential banking controls missing. Unfit for production.", tbl_cell_style)]
    ]
    grade_table = Table(grade_data, colWidths=[90, 110, 304])
    grade_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")])
    ]))
    story.append(grade_table)
    story.append(Spacer(1, 10))

    # Banking Security Control Matrix
    story.append(Paragraph("6. Core Banking Security Control Matrix (11 Controls)", h1_style))
    
    matrix_data = [
        [Paragraph("Domain", tbl_header_style), Paragraph("ID", tbl_header_style), Paragraph("Control Name", tbl_header_style), Paragraph("Target Standard", tbl_header_style)],
        [Paragraph("Auth & Session", tbl_cell_style), Paragraph("AUTH-01", tbl_cell_bold), Paragraph("Financial-Grade OAuth2 / FAPI DPoP Enforcer", tbl_cell_style), Paragraph("FAPI 1.0 / ASVS V2.1 L3", tbl_cell_style)],
        [Paragraph("Auth & Session", tbl_cell_style), Paragraph("AUTH-02", tbl_cell_bold), Paragraph("PSD2 RTS Strong Customer Authentication (SCA)", tbl_cell_style), Paragraph("PSD2 RTS / PCI 8.3", tbl_cell_style)],
        [Paragraph("Auth & Session", tbl_cell_style), Paragraph("AUTH-03", tbl_cell_bold), Paragraph("Anti-Clickjacking Frame Embedding Guard", tbl_cell_style), Paragraph("ASVS V14.4 / PCI 6.4", tbl_cell_style)],
        [Paragraph("Data Protection", tbl_cell_style), Paragraph("DATA-01", tbl_cell_bold), Paragraph("Field-Level Payload Encryption (JWE/AES-256)", tbl_cell_style), Paragraph("PCI-DSS v4.0 Req 3.4", tbl_cell_style)],
        [Paragraph("Data Protection", tbl_cell_style), Paragraph("DATA-02", tbl_cell_bold), Paragraph("Financial PII & PAN Data Masking Guard", tbl_cell_style), Paragraph("PCI-DSS v4.0 Req 3.3", tbl_cell_style)],
        [Paragraph("API Transport", tbl_cell_style), Paragraph("API-01", tbl_cell_bold), Paragraph("Mandatory TLS 1.3 & Strict HSTS Preloading", tbl_cell_style), Paragraph("ASVS V9.1 / FAPI 2.0", tbl_cell_style)],
        [Paragraph("API Transport", tbl_cell_style), Paragraph("API-02", tbl_cell_bold), Paragraph("API Gateway Rate-Limiting & Banner Removal", tbl_cell_style), Paragraph("OWASP API Top 10 API4", tbl_cell_style)],
        [Paragraph("Transaction", tbl_cell_style), Paragraph("TXN-01", tbl_cell_bold), Paragraph("Anti-Replay HMAC Request Signing", tbl_cell_style), Paragraph("FAPI 1.0 / OWASP API8", tbl_cell_style)],
        [Paragraph("Transaction", tbl_cell_style), Paragraph("TXN-02", tbl_cell_bold), Paragraph("Financial Idempotency Locking Engine", tbl_cell_style), Paragraph("PSD2 Article 4", tbl_cell_style)],
        [Paragraph("Audit & Compliance", tbl_cell_style), Paragraph("LOG-01", tbl_cell_bold), Paragraph("Tamper-Proof Audit Logging & Non-Repudiation", tbl_cell_style), Paragraph("PCI-DSS v4.0 Req 10.2", tbl_cell_style)],
        [Paragraph("Audit & Compliance", tbl_cell_style), Paragraph("LOG-02", tbl_cell_bold), Paragraph("Real-Time Fraud & Anomaly Detection Trigger", tbl_cell_style), Paragraph("PCI-DSS v4.0 Req 10.6", tbl_cell_style)]
    ]
    matrix_table = Table(matrix_data, colWidths=[90, 50, 224, 140])
    matrix_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")])
    ]))
    story.append(matrix_table)
    story.append(Spacer(1, 10))

    # Quickstart commands
    story.append(Paragraph("7. Operational Quickstart Commands", h1_style))
    story.append(Paragraph("<b>Local Execution (Node.js):</b>", h2_style))
    story.append(Paragraph("cd D:\\crazy_projects\\banksec-suite<br/>node server.js<br/># Access at http://localhost:8085", code_style))
    story.append(Paragraph("<b>Streamlit Cloud Live URL:</b>", h2_style))
    story.append(Paragraph("https://banksec-core-4q43jtsstksw55gvvtzcml.streamlit.app/", code_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    
    # Copy to artifacts directory as well
    import shutil
    shutil.copyfile(pdf_filename, artifact_filename)
    print(f"PDF successfully generated at {pdf_filename}")

if __name__ == '__main__':
    build_pdf()
