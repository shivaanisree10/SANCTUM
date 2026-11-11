import json
import hashlib
import hmac
from sanctum.verification.models import VerificationReport

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

class CertificateGenerator:
    """Generates PDF verification certificates and signs them."""
    
    # Mock symmetric key for demo purposes. In production, use KMS or RSA keys.
    SECRET_KEY = b"sanctum_secure_signing_key_mvp"
    
    @staticmethod
    def sign_report(report: VerificationReport) -> str:
        """Generates an HMAC-SHA256 signature for the certificate data to prevent tampering."""
        data_to_sign = f"{report.certificate_id}|{report.device_serial}|{report.result.value}|{report.device_hash_sha256}"
        signature = hmac.new(CertificateGenerator.SECRET_KEY, data_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        report.signature = signature
        return signature

    @staticmethod
    def verify_signature(report: VerificationReport) -> bool:
        """Verifies if the signature matches the report contents."""
        data_to_sign = f"{report.certificate_id}|{report.device_serial}|{report.result.value}|{report.device_hash_sha256}"
        expected = hmac.new(CertificateGenerator.SECRET_KEY, data_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(report.signature, expected)

    @staticmethod
    def generate_pdf(report: VerificationReport, output_path: str) -> None:
        """
        Generates PDF/A compliant output (if library supports).
        Falls back to .txt if fpdf is unavailable.
        """
        # Generate an HMAC-SHA256 signature (symmetric key based integrity seal)
        if not report.signature:
            CertificateGenerator.sign_report(report)
            
        if FPDF is None:
            text_path = output_path.replace('.pdf', '.txt')
            with open(text_path, "w", encoding="utf-8") as f:
                f.write("="*50 + "\n")
                f.write(" SANCTUM - CERTIFICATE OF ERASURE\n")
                f.write("="*50 + "\n\n")
                f.write(f"Certificate ID: {report.certificate_id}\n")
                f.write(f"Date/Time:      {report.timestamp}\n")
                f.write(f"Tool Version:   {report.tool_version}\n")
                f.write(f"Policy:         {report.policy_name} v{report.policy_version} ({report.passes_completed} passes)\n")
                f.write(f"Media Identity: {report.device_identity}\n")
                f.write(f"Serial/WWN:     {report.device_serial} / {report.device_wwn}\n")
                f.write(f"Capacity:       {report.capacity_bytes} bytes\n")
                f.write(f"Method:         {report.method}\n")
                f.write(f"Verif. Method:  {report.verification_method} (Coverage: {report.coverage})\n")
                f.write(f"Result:         {report.result.value}\n")
                f.write(f"Hash (SHA-256): {report.device_hash_sha256}\n")
                f.write(f"Defects:        {report.defects}\n")
                f.write(f"Operator:       {report.operator}\n")
                f.write(f"Work Order:     {report.work_order}\n")
                f.write(f"Disposition:    {report.disposition}\n")
                f.write(f"Residual Risk:  {report.residual_risk}\n")
                f.write(f"Audit Digest:   {report.audit_digest}\n")
                f.write(f"Errors:         {report.errors if report.errors else 'None'}\n\n")
                f.write("="*50 + "\n")
                f.write(f"HMAC-SHA256 INTEGRITY SEAL: {report.signature}\n")
                f.write("="*50 + "\n")
            return
            
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.cell(0, 10, "SANCTUM - Certificate of Erasure", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(5)
        
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 6, f"Certificate ID: {report.certificate_id}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Date/Time: {report.timestamp}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Tool Version: {report.tool_version}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Policy: {report.policy_name} v{report.policy_version} ({report.passes_completed} passes)", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Media Identity: {report.device_identity}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Serial: {report.device_serial} | WWN: {report.device_wwn}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Capacity: {report.capacity_bytes} bytes", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Method: {report.method}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Verification Method: {report.verification_method} (Coverage: {report.coverage})", new_x="LMARGIN", new_y="NEXT")
        
        if report.result.value == "PASS":
            pdf.set_text_color(0, 128, 0)
        elif report.result.value in ("FAIL", "QUARANTINE"):
            pdf.set_text_color(255, 0, 0)
            
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, f"Result: {report.result.value}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("helvetica", "", 10)
        
        pdf.cell(0, 6, f"Hash (SHA-256): {report.device_hash_sha256}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Defects: {report.defects}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Operator: {report.operator} | Work Order: {report.work_order}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Disposition: {report.disposition}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Residual Risk: {report.residual_risk}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Audit Digest: {report.audit_digest}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Errors: {report.errors if report.errors else 'None'}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(5)
        pdf.set_font("helvetica", "I", 8)
        pdf.cell(0, 6, f"HMAC-SHA256 Integrity Seal: {report.signature}", new_x="LMARGIN", new_y="NEXT")
        
        # In a full environment, we would generate a QR code image and embed it here using:
        # qrcode.make(...) and pdf.image(...)
        
        pdf.output(output_path)
