import pytest
import os
from pathlib import Path

from sanctum.dal import VirtualDevice
from sanctum.audit import AuditWriter
from sanctum.policies import ErasurePolicy, MediaClass, VerificationRequirement
from sanctum.erasure.patterns import PatternType
from sanctum.verification import ErasureVerifier, CertificateGenerator, VerificationResult

def create_dummy_file(path: Path, pattern: bytes, size: int):
    with open(path, "wb") as f:
        f.write(pattern * (size // len(pattern)))

@pytest.fixture
def test_policy() -> ErasurePolicy:
    return ErasurePolicy(
        name="TEST-Verify",
        description="test",
        reference="none",
        category="test",
        passes=[PatternType.ZERO],
        verification=VerificationRequirement.LAST_PASS,
        applicable_media=[MediaClass.ANY],
        version="1.0"
    )

def test_verification_pass(tmp_path: Path, test_policy: ErasurePolicy) -> None:
    img_path = tmp_path / "pass.img"
    audit_path = tmp_path / "audit.log"
    create_dummy_file(img_path, b"\x00", 1024)
    
    device = VirtualDevice(img_path)
    audit = AuditWriter(str(audit_path))
    verifier = ErasureVerifier(device, audit, "JOB-123")
    
    report = verifier.verify(test_policy)
    
    assert report.result == VerificationResult.PASS
    assert report.errors == ""
    assert len(report.device_hash_sha256) == 64
    assert report.disposition == "SANITIZED"
    assert report.residual_risk == "NONE"
    
    # Check that audit log has VERIFICATION_START and VERIFICATION_END
    audit_content = audit_path.read_text(encoding="utf-8")
    assert "VERIFICATION_START" in audit_content
    assert "VERIFICATION_END" in audit_content
    assert "PASS" in audit_content
    
    device.close()

def test_verification_fail_residual_data(tmp_path: Path, test_policy: ErasurePolicy) -> None:
    img_path = tmp_path / "fail.img"
    audit_path = tmp_path / "audit.log"
    # Create image with ones instead of zeroes
    create_dummy_file(img_path, b"\xFF", 1024)
    
    device = VirtualDevice(img_path)
    audit = AuditWriter(str(audit_path))
    verifier = ErasureVerifier(device, audit, "JOB-124")
    
    report = verifier.verify(test_policy)
    
    assert report.result == VerificationResult.FAIL
    assert "Block mismatch" in report.errors
    assert report.disposition == "QUARANTINED"
    assert report.residual_risk == "HIGH"
    
    audit_content = audit_path.read_text(encoding="utf-8")
    assert "FAIL" in audit_content
    
    device.close()

def test_certificate_signature_and_generation(tmp_path: Path, test_policy: ErasurePolicy) -> None:
    img_path = tmp_path / "cert.img"
    audit_path = tmp_path / "audit.log"
    cert_path = str(tmp_path / "cert.pdf")
    
    create_dummy_file(img_path, b"\x00", 1024)
    
    device = VirtualDevice(img_path)
    audit = AuditWriter(str(audit_path))
    verifier = ErasureVerifier(device, audit, "JOB-125")
    
    report = verifier.verify(test_policy)
    CertificateGenerator.generate_pdf(report, cert_path)
    
    assert report.signature != ""
    assert CertificateGenerator.verify_signature(report) is True
    
    # Tamper with the report and verify signature fails
    report.result = VerificationResult.FAIL
    assert CertificateGenerator.verify_signature(report) is False
    
    # Since fpdf might not be installed, it falls back to .txt
    if os.path.exists(cert_path.replace(".pdf", ".txt")):
        content = Path(cert_path.replace(".pdf", ".txt")).read_text(encoding="utf-8")
        assert "SANCTUM - CERTIFICATE OF ERASURE" in content
        assert report.certificate_id in content
        assert report.signature in content
    else:
        assert os.path.exists(cert_path)
        
    device.close()
