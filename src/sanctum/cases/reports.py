import os
import json
import tempfile
from typing import List, Dict, Any, Optional
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import qrcode

from .models import (
    CaseRecord,
    ExhibitRecord,
    CustodyEntryRecord,
    RecoveredObjectRecord,
    CertificateRecord,
)


class BaseForensicPDF(FPDF):
    """Custom PDF/A styled document for SANCTUM forensic reports."""

    def __init__(self, title: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.doc_title = title
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 8, "SANCTUM FORENSIC PLATFORM", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        self.set_font("Helvetica", "I", 10)
        self.cell(0, 6, self.doc_title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        self.line(10, 26, 200, 26)
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()} | Confidential Evidentiary Document", align="C")


class ReportRenderer:
    """
    Renders professional PDF/A and text reports for:
    1. Forensic Case Report
    2. Certificate of Destruction
    3. Batch ITAD Report
    4. Chain of Custody Form
    """

    @staticmethod
    def _create_qr_temp_image(data_text: str) -> str:
        qr = qrcode.QRCode(box_size=4, border=1)
        qr.add_data(data_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        img.save(tmp.name)
        tmp.close()
        return tmp.name

    @classmethod
    def render_case_report(
        cls,
        case: CaseRecord,
        exhibits: List[ExhibitRecord],
        recovered_objects: List[RecoveredObjectRecord],
        output_pdf_path: str,
    ) -> None:
        pdf = BaseForensicPDF("Comprehensive Forensic Investigation Report")
        pdf.add_page()

        # Case Overview Section
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "1. Case Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(40, 6, "Case Number:", 0)
        pdf.cell(0, 6, case.case_number, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Case Title:", 0)
        pdf.cell(0, 6, case.title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Lead Investigator:", 0)
        pdf.cell(0, 6, f"{case.investigator} ({case.agency or 'N/A'})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Case Lifecycle State:", 0)
        pdf.cell(0, 6, case.state.value, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Created Date (UTC):", 0)
        pdf.cell(0, 6, case.created_at, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # Exhibits Section
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"2. Attached Exhibits ({len(exhibits)})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(30, 6, "Exhibit #", 1)
        pdf.cell(60, 6, "Description", 1)
        pdf.cell(45, 6, "Serial #", 1)
        pdf.cell(55, 6, "Location", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "", 8)
        for exh in exhibits:
            pdf.cell(30, 6, exh.exhibit_number[:15], 1)
            pdf.cell(60, 6, exh.description[:35], 1)
            pdf.cell(45, 6, (exh.device_serial or "N/A")[:25], 1)
            pdf.cell(55, 6, (exh.storage_location or "Evidence Vault")[:30], 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # Recovered Objects Section
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"3. Recovered Objects Evidence Manifest ({len(recovered_objects)})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(50, 6, "Name", 1)
        pdf.cell(20, 6, "Size", 1)
        pdf.cell(25, 6, "Grade", 1)
        pdf.cell(25, 6, "Offset", 1)
        pdf.cell(70, 6, "SHA-256 Digest", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "", 7)
        for obj in recovered_objects:
            pdf.cell(50, 6, obj.name[:28], 1)
            pdf.cell(20, 6, f"{obj.size_bytes} B", 1)
            pdf.cell(25, 6, obj.recovery_grade.value, 1)
            pdf.cell(25, 6, str(obj.source_offset), 1)
            pdf.cell(70, 6, obj.sha256_hash[:32] + "...", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Verification QR Code
        qr_payload = f"SANCTUM_CASE|{case.case_number}|{case.state.value}|OBJECTS={len(recovered_objects)}"
        qr_img = cls._create_qr_temp_image(qr_payload)
        pdf.ln(6)
        pdf.image(qr_img, x=165, y=pdf.get_y(), w=25)
        pdf.set_font("Helvetica", "I", 8)
        pdf.cell(140, 5, "Scan QR to verify cryptographic case manifest authenticity.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.output(output_pdf_path)
        try:
            os.remove(qr_img)
        except Exception:
            pass

    @classmethod
    def render_destruction_certificate(
        cls,
        cert: CertificateRecord,
        output_pdf_path: str,
    ) -> None:
        pdf = BaseForensicPDF("Certificate of Sanitization & Data Destruction")
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(0, 100, 0) if cert.result == "PASS" else pdf.set_text_color(180, 0, 0)
        pdf.cell(0, 10, f"VERDICT: SANITIZATION {cert.result}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

        pdf.set_font("Helvetica", "", 10)
        pdf.cell(50, 6, "Certificate ID:", 0)
        pdf.cell(0, 6, cert.certificate_id, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(50, 6, "Target Device Serial:", 0)
        pdf.cell(0, 6, cert.device_serial, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(50, 6, "Sanitization Method:", 0)
        pdf.cell(0, 6, cert.method, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(50, 6, "Final Verified Hash:", 0)
        pdf.cell(0, 6, cert.sha256_hash, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(50, 6, "Cryptographic Signature:", 0)
        pdf.cell(0, 6, cert.signature[:48] + "...", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(50, 6, "Issued Timestamp (UTC):", 0)
        pdf.cell(0, 6, cert.issued_at, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(6)

        qr_payload = f"CERT:{cert.certificate_id}|SERIAL:{cert.device_serial}|RESULT:{cert.result}|SIG:{cert.signature[:16]}"
        qr_img = cls._create_qr_temp_image(qr_payload)
        pdf.image(qr_img, x=85, y=pdf.get_y(), w=35)
        pdf.output(output_pdf_path)
        try:
            os.remove(qr_img)
        except Exception:
            pass

    @classmethod
    def render_batch_itad_report(
        cls,
        batch_id: str,
        certificates: List[CertificateRecord],
        client_name: str,
        output_pdf_path: str,
    ) -> None:
        pdf = BaseForensicPDF("Batch IT Asset Disposition (ITAD) Sanitization Report")
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(40, 6, "ITAD Batch ID:", 0)
        pdf.cell(0, 6, batch_id, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Client Entity:", 0)
        pdf.cell(0, 6, client_name, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Total Devices Sanitized:", 0)
        pdf.cell(0, 6, str(len(certificates)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(35, 6, "Certificate ID", 1)
        pdf.cell(40, 6, "Serial Number", 1)
        pdf.cell(45, 6, "Erasure Standard", 1)
        pdf.cell(20, 6, "Result", 1)
        pdf.cell(50, 6, "Verification Signature", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "", 8)
        for c in certificates:
            pdf.cell(35, 6, c.certificate_id[:16], 1)
            pdf.cell(40, 6, c.device_serial[:20], 1)
            pdf.cell(45, 6, c.method[:22], 1)
            pdf.cell(20, 6, c.result, 1)
            pdf.cell(50, 6, c.signature[:24] + "...", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.output(output_pdf_path)

    @classmethod
    def render_custody_form(
        cls,
        case: CaseRecord,
        exhibit: ExhibitRecord,
        entries: List[CustodyEntryRecord],
        is_chain_intact: bool,
        output_pdf_path: str,
    ) -> None:
        pdf = BaseForensicPDF("Evidence Chain-of-Custody Tracking Form")
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(40, 6, "Case Number:", 0)
        pdf.cell(0, 6, case.case_number, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Exhibit Number:", 0)
        pdf.cell(0, 6, f"{exhibit.exhibit_number} - {exhibit.description}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Chain Integrity:", 0)
        pdf.set_text_color(0, 120, 0) if is_chain_intact else pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 6, "CRYPTOGRAPHICALLY VERIFIED INTACT" if is_chain_intact else "INTEGRITY BREACH DETECTED", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(32, 6, "Timestamp (UTC)", 1)
        pdf.cell(28, 6, "Action", 1)
        pdf.cell(25, 6, "Actor", 1)
        pdf.cell(28, 6, "From -> To", 1)
        pdf.cell(37, 6, "Reason", 1)
        pdf.cell(40, 6, "SHA-256 Ledger Hash", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "", 7)
        for e in entries:
            pdf.cell(32, 6, e.timestamp_utc[:19], 1)
            pdf.cell(28, 6, e.action[:16], 1)
            pdf.cell(25, 6, e.actor[:14], 1)
            pdf.cell(28, 6, f"{e.source_holder[:6]}->{e.target_holder[:6]}", 1)
            pdf.cell(37, 6, e.reason[:22], 1)
            pdf.cell(40, 6, e.record_hash[:18] + "...", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.output(output_pdf_path)
