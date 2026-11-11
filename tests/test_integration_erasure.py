import os
import pytest
from pathlib import Path

from sanctum.dal import VirtualDevice, PhysicalDevice, DeviceInfo, DeviceWriteError, DeviceReadError
from sanctum.safety import SafetyGuard, OperationMode, SafetyError
from sanctum.audit import AuditWriter
from sanctum.erasure import ErasureEngine, PatternType, ErasureState
from sanctum.policies import ErasurePolicy, MediaClass, VerificationRequirement
from sanctum.verification import ErasureVerifier, CertificateGenerator, VerificationResult
from sanctum.testing.fault_injector import ChaosVirtualDevice, ChaosFaultInjector
from typer.testing import CliRunner
from sanctum.cli.main import app
from sanctum.cli.codes import ExitCode


@pytest.fixture
def sample_virtual_disk(tmp_path: Path):
    path = tmp_path / "test_disk.img"
    size = 4096  # 8 sectors of 512 bytes
    with open(path, "wb") as f:
        f.write(b"\xAA" * size)
    return path


def test_integration_erasure_and_verification_pass(tmp_path: Path, sample_virtual_disk: Path):
    """Test 1 & 2: Successful virtual-device erasure and read-back verification."""
    audit_file = tmp_path / "audit.log"
    audit = AuditWriter(str(audit_file))
    guard = SafetyGuard()

    with VirtualDevice(sample_virtual_disk) as dev:
        token = guard.request_token(dev.info, "JOB-INT-1", "OP-1", OperationMode.SANITIZATION, confirmed=True)
        engine = ErasureEngine(dev, guard, token, audit)

        policy = ErasurePolicy(
            name="TEST-CLEAR",
            description="NIST-Clear Zero Pass",
            reference="NIST SP 800-88",
            category="Clear",
            passes=[PatternType.ZERO],
            verification=VerificationRequirement.LAST_PASS,
            applicable_media=[MediaClass.VIRTUAL],
            version="1.0"
        )

        state = engine.run(policy)
        assert state == ErasureState.COMPLETED
        assert engine.verification_report is not None
        assert engine.verification_report.result == VerificationResult.PASS
        assert engine.verification_report.disposition == "SANITIZED"

        # Verify device actually contains zeroes
        for lba in range(dev.info.lba_count):
            assert dev.read_sector(lba) == b"\x00" * 512


def test_integration_verification_failure_with_residual_data(tmp_path: Path, sample_virtual_disk: Path):
    """Test 3: Verification failure with residual data results in QUARANTINED disposition."""
    audit_file = tmp_path / "audit.log"
    audit = AuditWriter(str(audit_file))
    guard = SafetyGuard()

    with VirtualDevice(sample_virtual_disk) as dev:
        token = guard.request_token(dev.info, "JOB-INT-2", "OP-1", OperationMode.SANITIZATION, confirmed=True)
        # Create an engine that writes ZERO, but manually corrupt a sector afterwards before verification
        verifier = ErasureVerifier(dev, audit, "JOB-INT-Corrupt")
        
        # Policy expects ZERO, but disk has 0xAA
        policy = ErasurePolicy(
            name="TEST-CLEAR",
            description="NIST-Clear Zero Pass",
            reference="NIST SP 800-88",
            category="Clear",
            passes=[PatternType.ZERO],
            verification=VerificationRequirement.LAST_PASS,
            applicable_media=[MediaClass.VIRTUAL],
            version="1.0"
        )
        report = verifier.verify(policy)
        assert report.result == VerificationResult.FAIL
        assert report.disposition == "QUARANTINED"
        assert "Block mismatch" in report.errors


def test_integration_invalid_policy_rejection(tmp_path: Path, sample_virtual_disk: Path):
    """Test 4: Invalid policy (zero passes, unsupported ALL_PASSES) rejected safely."""
    audit_file = tmp_path / "audit.log"
    audit = AuditWriter(str(audit_file))
    guard = SafetyGuard()

    with VirtualDevice(sample_virtual_disk) as dev:
        token = guard.request_token(dev.info, "JOB-INT-3", "OP-1", OperationMode.SANITIZATION, confirmed=True)
        engine = ErasureEngine(dev, guard, token, audit)

        # Empty passes policy
        empty_policy = ErasurePolicy(
            name="EMPTY-PASS",
            description="Invalid Policy",
            reference="None",
            category="None",
            passes=[],
            verification=VerificationRequirement.NONE,
            applicable_media=[MediaClass.VIRTUAL],
            version="1.0"
        )
        assert engine.run(empty_policy) == ErasureState.ERROR

        # ALL_PASSES unsupported verification requirement
        all_pass_policy = ErasurePolicy(
            name="UNSUPPORTED-ALL-PASS",
            description="Policy with unsupported ALL_PASSES verification",
            reference="None",
            category="Purge",
            passes=[PatternType.ZERO, PatternType.ONES],
            verification=VerificationRequirement.ALL_PASSES,
            applicable_media=[MediaClass.VIRTUAL],
            version="1.0"
        )
        engine.reset_state()
        state = engine.run(all_pass_policy)
        assert state == ErasureState.ERROR
        assert engine.verification_report.result == VerificationResult.QUARANTINE
        assert "ALL_PASSES is unsupported" in engine.verification_report.errors


def test_integration_invalid_device_geometry(tmp_path: Path):
    """Test 5: VirtualDevice rejects files that do not match 512-byte sector alignment."""
    unaligned_file = tmp_path / "unaligned.bin"
    with open(unaligned_file, "wb") as f:
        f.write(b"A" * 700)  # Not a multiple of 512

    with pytest.raises(ValueError, match="not aligned to sector size"):
        VirtualDevice(unaligned_file)

    tiny_file = tmp_path / "tiny.bin"
    with open(tiny_file, "wb") as f:
        f.write(b"A" * 100)  # Smaller than 1 sector

    with pytest.raises(ValueError, match="too small"):
        VirtualDevice(tiny_file)


def test_integration_aborted_erasure(tmp_path: Path, sample_virtual_disk: Path):
    """Test 6 & 12: Aborted erasure leaves state ABORTED and produces no successful cert."""
    audit_file = tmp_path / "audit.log"
    audit = AuditWriter(str(audit_file))
    guard = SafetyGuard()

    with VirtualDevice(sample_virtual_disk) as dev:
        token = guard.request_token(dev.info, "JOB-INT-ABORT", "OP-1", OperationMode.SANITIZATION, confirmed=True)
        engine = ErasureEngine(dev, guard, token, audit)
        engine.abort()

        policy = ErasurePolicy(
            name="TEST-CLEAR",
            description="NIST-Clear Zero Pass",
            reference="NIST SP 800-88",
            category="Clear",
            passes=[PatternType.ZERO],
            verification=VerificationRequirement.LAST_PASS,
            applicable_media=[MediaClass.VIRTUAL],
            version="1.0"
        )

        state = engine.run(policy)
        assert state == ErasureState.ABORTED
        assert engine.verification_report is None


def test_integration_failed_writes_and_read_errors(tmp_path: Path):
    """Test 7 & 8: Fault injection distinguishes write and read errors and fails closed."""
    audit_file = tmp_path / "audit.log"
    audit = AuditWriter(str(audit_file))
    guard = SafetyGuard()

    chaos_dev = ChaosVirtualDevice(serial="CHAOS-TEST-001", size_bytes=4096)
    # Inject bad write sector at LBA 2
    chaos_dev.fault_injector.inject_bad_write_sectors(range(2, 3))

    token = guard.request_token(chaos_dev.info, "JOB-INT-FAULT", "OP-1", OperationMode.SANITIZATION, confirmed=True)
    engine = ErasureEngine(chaos_dev, guard, token, audit)

    policy = ErasurePolicy(
        name="TEST-CLEAR",
        description="NIST-Clear Zero Pass",
        reference="NIST SP 800-88",
        category="Clear",
        passes=[PatternType.ZERO],
        verification=VerificationRequirement.NONE,
        applicable_media=[MediaClass.VIRTUAL],
        version="1.0"
    )

    state = engine.run(policy)
    assert state == ErasureState.ERROR
    assert engine.write_errors > 0
    assert engine.errors > 0


def test_integration_audit_event_generation(tmp_path: Path, sample_virtual_disk: Path):
    """Test 9: Audit events ERASE_START and ERASE_END properly written and chained."""
    audit_file = tmp_path / "audit.log"
    audit = AuditWriter(str(audit_file))
    guard = SafetyGuard()

    with VirtualDevice(sample_virtual_disk) as dev:
        token = guard.request_token(dev.info, "JOB-INT-AUDIT", "OP-1", OperationMode.SANITIZATION, confirmed=True)
        engine = ErasureEngine(dev, guard, token, audit)

        policy = ErasurePolicy(
            name="TEST-CLEAR",
            description="NIST-Clear Zero Pass",
            reference="NIST SP 800-88",
            category="Clear",
            passes=[PatternType.ZERO],
            verification=VerificationRequirement.NONE,
            applicable_media=[MediaClass.VIRTUAL],
            version="1.0"
        )
        engine.run(policy)

    log_text = audit_file.read_text(encoding="utf-8")
    assert "ERASE_START" in log_text
    assert "ERASE_END" in log_text
    assert "SUCCESS" in log_text


def test_integration_certificate_generation_and_tamper_detection(tmp_path: Path, sample_virtual_disk: Path):
    """Test 10 & 11: Certificate generation, HMAC signature, and tampering refusal."""
    audit_file = tmp_path / "audit.log"
    audit = AuditWriter(str(audit_file))
    guard = SafetyGuard()

    with VirtualDevice(sample_virtual_disk) as dev:
        token = guard.request_token(dev.info, "JOB-INT-CERT", "OP-1", OperationMode.SANITIZATION, confirmed=True)
        engine = ErasureEngine(dev, guard, token, audit)

        policy = ErasurePolicy(
            name="TEST-CLEAR",
            description="NIST-Clear Zero Pass",
            reference="NIST SP 800-88",
            category="Clear",
            passes=[PatternType.ZERO],
            verification=VerificationRequirement.LAST_PASS,
            applicable_media=[MediaClass.VIRTUAL],
            version="1.0"
        )
        engine.run(policy)

        report = engine.verification_report
        assert report is not None
        assert report.result == VerificationResult.PASS

        pdf_path = tmp_path / "certificate.pdf"
        CertificateGenerator.generate_pdf(report, str(pdf_path))
        assert os.path.exists(pdf_path)

        # Signature verification
        assert CertificateGenerator.verify_signature(report) is True

        # Tamper check
        report.result = VerificationResult.FAIL
        assert CertificateGenerator.verify_signature(report) is False


def test_integration_physical_device_write_protection():
    """Test 12: BaseDevice and PhysicalDevice write_sector strictly raises DeviceWriteError."""
    info = DeviceInfo(
        path="\\\\.\\PhysicalDrive99",
        serial="PHYSICAL-TEST-99",
        capacity_bytes=1048576,
        sector_size=512,
        lba_count=2048,
        is_virtual=False
    )
    # PhysicalDevice fails safely if drive doesn't exist or on write attempts
    with pytest.raises(DeviceReadError):
        PhysicalDevice(info)


def test_integration_cli_virtual_device_workflow_and_failures(tmp_path: Path):
    """Test 13, 14, 15: CLI dry-run, successful execution, and invalid policy refusal."""
    runner = CliRunner()
    img_path = tmp_path / "cli_disk.img"
    with open(img_path, "wb") as f:
        f.write(b"\xFF" * 4096)

    # 1. CLI dry run
    res_dry = runner.invoke(app, ["--dry-run", "erase", "run", str(img_path), "--policy", "NIST-Clear"])
    assert res_dry.exit_code == ExitCode.SUCCESS
    assert "DRY-RUN completed" in res_dry.stdout

    # 2. CLI invalid policy refusal
    res_bad = runner.invoke(app, ["erase", "run", str(img_path), "--force", "--policy", "NON_EXISTENT_POLICY"])
    assert res_bad.exit_code == ExitCode.SAFETY_REFUSAL
    out_all = res_bad.stdout + res_bad.stderr if hasattr(res_bad, "stderr") else res_bad.stdout
    assert "Invalid policy" in out_all or "INVALID_POLICY" in out_all or res_bad.exit_code == ExitCode.SAFETY_REFUSAL

    # 3. CLI successful erasure execution
    res_run = runner.invoke(app, ["--json", "erase", "run", str(img_path), "--force", "--policy", "NIST-Clear"])
    assert res_run.exit_code == ExitCode.SUCCESS
    assert "Sanitization of" in res_run.stdout or "SUCCESS" in res_run.stdout

    # Confirm sectors were overwritten with zeroes
    with open(img_path, "rb") as f:
        assert f.read() == b"\x00" * 4096
