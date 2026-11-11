import os
import zipfile
import pytest
from sanctum.cases.models import CaseState, RecoveryGrade
from sanctum.cases.db import CaseDatabase, CaseLifecycleError
from sanctum.cases.reports import ReportRenderer
from sanctum.cases.export import CaseExporter
from sanctum.safety.guard import SafetyGuard, SafetyError
from sanctum.safety.models import OperationMode
from sanctum.dal import DeviceInfo


def test_case_lifecycle(tmp_path):
    db_path = str(tmp_path / "test_case.db")
    db = CaseDatabase(db_path)

    # 1. CREATE
    case = db.create_case("CASE-2026-001", "Espionage Incident", "Agent Smith", "Cyber Division")
    assert case.state == CaseState.CREATED
    assert case.case_number == "CASE-2026-001"

    # Invalid jump from CREATED to PROCESS directly
    with pytest.raises(CaseLifecycleError):
        db.transition_state(case.case_id, CaseState.PROCESS)

    # 2. OPEN
    case = db.transition_state(case.case_id, CaseState.OPEN)
    assert case.state == CaseState.OPEN

    # 3. ATTACH EXHIBIT
    case = db.transition_state(case.case_id, CaseState.ATTACH_EXHIBIT)
    assert case.state == CaseState.ATTACH_EXHIBIT

    exhibit = db.add_exhibit(
        case.case_id,
        "EXH-01",
        "Target NVMe Drive",
        device_serial="SAMSUNG-NVME-SECURE-999",
        received_from="Field Agent Alpha",
        storage_location="Vault A-12",
    )
    assert exhibit.exhibit_number == "EXH-01"

    # 4. PROCESS
    case = db.transition_state(case.case_id, CaseState.PROCESS)
    assert case.state == CaseState.PROCESS

    # 5. CLOSE
    case = db.transition_state(case.case_id, CaseState.CLOSED)
    assert case.state == CaseState.CLOSED
    assert case.closed_at is not None

    # Adding exhibit to closed case should fail
    with pytest.raises(CaseLifecycleError):
        db.add_exhibit(case.case_id, "EXH-02", "Extra USB")


def test_chain_of_custody_hash_linking(tmp_path):
    db = CaseDatabase(str(tmp_path / "custody.db"))
    case = db.create_case("CUSTODY-01", "Chain Test", "Examiner")
    db.transition_state(case.case_id, CaseState.OPEN)
    db.transition_state(case.case_id, CaseState.ATTACH_EXHIBIT)

    exh = db.add_exhibit(case.case_id, "EXH-A", "Seized Laptop Hard Drive")

    # Exhibit creation logs initial seizure entry
    entries = db.list_custody_entries(exhibit_id=exh.exhibit_id)
    assert len(entries) == 1
    assert db.verify_custody_chain(exh.exhibit_id) is True

    # Transfer 1: Lab Intake
    entry2 = db.add_custody_entry(
        case.case_id,
        exh.exhibit_id,
        action="TRANSFER_TO_LAB",
        actor="Examiner",
        source_holder="Evidence Locker",
        target_holder="Forensic Imaging Station",
        reason="Acquisition of master image",
    )
    assert entry2.prev_record_hash == entries[0].record_hash
    assert db.verify_custody_chain(exh.exhibit_id) is True

    # Transfer 2: Return to vault
    entry3 = db.add_custody_entry(
        case.case_id,
        exh.exhibit_id,
        action="RETURN_TO_VAULT",
        actor="Examiner",
        source_holder="Forensic Imaging Station",
        target_holder="Evidence Locker",
        reason="Forensic acquisition complete",
    )
    assert entry3.prev_record_hash == entry2.record_hash
    assert db.verify_custody_chain(exh.exhibit_id) is True

    # Tamper detection: artificially modify an entry in SQLite
    with db._conn:
        db._conn.execute(
            "UPDATE custody_entries SET actor = 'Malicious Actor' WHERE entry_id = ?",
            (entry2.entry_id,),
        )
    assert db.verify_custody_chain(exh.exhibit_id) is False


def test_safety_rule_open_case_prevents_sanitization(tmp_path):
    db = CaseDatabase(str(tmp_path / "safety_test.db"))
    guard = SafetyGuard(case_db=db)

    # Register device and attach to an open case
    case = db.create_case("SAFETY-01", "Forensic Lock Test", "Agent")
    db.transition_state(case.case_id, CaseState.OPEN)
    db.transition_state(case.case_id, CaseState.ATTACH_EXHIBIT)

    serial = "CRITICAL-EVIDENCE-DISK-777"
    exh = db.add_exhibit(case.case_id, "EXH-01", "Primary Suspect Drive", device_serial=serial)
    db.register_device(serial=serial, case_id=case.case_id, exhibit_id=exh.exhibit_id, is_forensic_hold=True)

    dev_info = DeviceInfo(
        path="/dev/evidence",
        serial=serial,
        capacity_bytes=512 * 1024 * 1024,
        sector_size=512,
        lba_count=1024 * 1024,
        is_virtual=True,
    )

    # Attempting to sanitize while case is open MUST be blocked
    with pytest.raises(SafetyError) as exc_info:
        guard.request_token(
            device=dev_info,
            job_id="JOB-SANITIZE",
            operation_id="OP-ERASE",
            mode=OperationMode.SANITIZATION,
            confirmed=True,
        )
    assert "attached to an active forensic case" in str(exc_info.value)

    # Move case to PROCESS, still should be blocked
    db.transition_state(case.case_id, CaseState.PROCESS)
    with pytest.raises(SafetyError):
        guard.request_token(
            device=dev_info,
            job_id="JOB-SANITIZE",
            operation_id="OP-ERASE",
            mode=OperationMode.SANITIZATION,
            confirmed=True,
        )

    # Now close the case
    db.transition_state(case.case_id, CaseState.CLOSED)
    # Once closed, device is no longer blocked by the open case safety rule
    tok = guard.request_token(
        device=dev_info,
        job_id="JOB-SANITIZE-OK",
        operation_id="OP-ERASE",
        mode=OperationMode.SANITIZATION,
        confirmed=True,
    )
    assert tok.is_valid()


def test_recovered_objects_manifest_and_provenance(tmp_path):
    db = CaseDatabase(str(tmp_path / "objects.db"))
    case = db.create_case("REC-01", "Recovery Manifest", "Lead Investigator")

    obj1 = db.add_recovered_object(
        case_id=case.case_id,
        name="credentials.xlsx",
        extension="xlsx",
        size_bytes=45200,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recovery_grade=RecoveryGrade.INTACT,
        source_offset=10485760,
        source_lba=20480,
        provenance="MFT Entry 421 / Allocated Inode 198",
    )
    assert obj1.recovery_grade == RecoveryGrade.INTACT
    assert obj1.source_offset == 10485760

    obj2 = db.add_recovered_object(
        case_id=case.case_id,
        name="carved_image.jpg",
        extension="jpg",
        size_bytes=102400,
        sha256_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        recovery_grade=RecoveryGrade.CARVED,
        source_offset=52428800,
        source_lba=102400,
        provenance="Aho-Corasick Carved from Unallocated Space",
    )

    objects = db.list_recovered_objects(case.case_id)
    assert len(objects) == 2
    assert objects[0].name == "credentials.xlsx"
    assert objects[1].recovery_grade == RecoveryGrade.CARVED


def test_pdf_report_generation(tmp_path):
    db = CaseDatabase(str(tmp_path / "reports_test.db"))
    case = db.create_case("REPORT-01", "Malware Incident", "Analyst Doe")
    exhibit = db.add_exhibit(case.case_id, "EXH-001", "USB Flash Drive")
    db.add_recovered_object(
        case_id=case.case_id,
        name="trojan.exe",
        extension="exe",
        size_bytes=20480,
        sha256_hash="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        recovery_grade=RecoveryGrade.INTACT,
        source_offset=4096,
        provenance="FAT32 Root Directory Entry",
    )

    cert = db.record_certificate(
        certificate_id="CERT-DEST-001",
        certificate_type="DESTRUCTION",
        device_serial="USB-FLASH-1234",
        result="PASS",
        method="NIST 800-88 Rev 1 Purge",
        sha256_hash="0000000000000000000000000000000000000000000000000000000000000000",
        signature="SIGNATURE_HMAC_TEST_ABC",
        case_id=case.case_id,
    )

    # 1. Forensic Case Report
    case_pdf = str(tmp_path / "case_report.pdf")
    ReportRenderer.render_case_report(
        case=case,
        exhibits=[exhibit],
        recovered_objects=db.list_recovered_objects(case.case_id),
        output_pdf_path=case_pdf,
    )
    assert os.path.exists(case_pdf) and os.path.getsize(case_pdf) > 1000

    # 2. Certificate of Destruction
    cert_pdf = str(tmp_path / "cert.pdf")
    ReportRenderer.render_destruction_certificate(cert, cert_pdf)
    assert os.path.exists(cert_pdf) and os.path.getsize(cert_pdf) > 1000

    # 3. Batch ITAD Report
    itad_pdf = str(tmp_path / "itad.pdf")
    ReportRenderer.render_batch_itad_report("BATCH-ITAD-2026", [cert], "Acme Corp", itad_pdf)
    assert os.path.exists(itad_pdf) and os.path.getsize(itad_pdf) > 1000

    # 4. Chain of Custody Form
    custody_pdf = str(tmp_path / "custody.pdf")
    entries = db.list_custody_entries(exhibit_id=exhibit.exhibit_id)
    ReportRenderer.render_custody_form(case, exhibit, entries, True, custody_pdf)
    assert os.path.exists(custody_pdf) and os.path.getsize(custody_pdf) > 1000


def test_case_export_and_independent_verification(tmp_path):
    db = CaseDatabase(str(tmp_path / "export_test.db"))
    case = db.create_case("EXP-2026-X", "Exportable Case", "Lead Specialist")
    db.transition_state(case.case_id, CaseState.OPEN)
    db.transition_state(case.case_id, CaseState.ATTACH_EXHIBIT)

    exh = db.add_exhibit(case.case_id, "EXH-99", "Smartphone Storage Chip")
    db.add_custody_entry(
        case.case_id,
        exh.exhibit_id,
        action="TRANSFER_FOR_CHIP_OFF",
        actor="Specialist",
        source_holder="Vault",
        target_holder="Hardware Lab",
        reason="Chip-off extraction",
    )

    db.add_recovered_object(
        case_id=case.case_id,
        name="chats.db",
        extension="db",
        size_bytes=98304,
        sha256_hash="2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        recovery_grade=RecoveryGrade.INTACT,
        source_offset=65536,
        provenance="Extracted from raw eMMC dump",
    )

    export_zip = str(tmp_path / "case_export.zip")
    manifest = CaseExporter.export_case(
        case_db=db,
        case_id=case.case_id,
        export_zip_path=export_zip,
        audit_log_entries=[{"event": "CASE_EXPORTED", "operator": "Specialist"}],
    )
    assert os.path.exists(export_zip)
    assert manifest["case"]["case_number"] == "EXP-2026-X"

    # Verify self-contained case export
    verif = CaseExporter.verify_exported_case(export_zip)
    assert verif["valid"] is True
    assert verif["custody_intact"] is True
    assert verif["verified_files"] >= 3
    assert verif["manifest_details"]["case_number"] == "EXP-2026-X"

    # Test tampering detection on exported archive:
    corrupt_zip = str(tmp_path / "corrupt_case_export.zip")
    with zipfile.ZipFile(export_zip, "r") as src, zipfile.ZipFile(corrupt_zip, "w") as dst:
        for item in src.infolist():
            content = src.read(item.filename)
            if item.filename == "manifest.json":
                # Alter manifest content
                content = content.replace(b"EXP-2026-X", b"TAMPERED-CASE")
            dst.writestr(item, content)

    corrupt_verif = CaseExporter.verify_exported_case(corrupt_zip)
    assert corrupt_verif["valid"] is False
    assert any("manifest.json" in err for err in corrupt_verif["errors"])
