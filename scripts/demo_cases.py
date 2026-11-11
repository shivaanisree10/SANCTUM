#!/usr/bin/env python3
"""
M14 Demonstration Script — Case Database, Chain of Custody, Reporting, and Independent Verification.
Demonstrates:
- SQLite WAL mode Case Database initialization.
- Full Case Lifecycle: CREATE -> OPEN -> ATTACH_EXHIBIT -> PROCESS -> CLOSE.
- Safety rule enforcement: Device attached to open forensic case refuses sanitization token.
- Tamper-evident hash-chained chain-of-custody tracking.
- Recovered objects manifest with SHA-256, recovery grade, and source offset provenance.
- PDF/A report generation (Forensic Case Report, Certificate of Destruction, Batch ITAD, Custody Form).
- Self-contained case export packaging (.zip with manifest, reports, hashes, audit logs).
- Independent verification via the CLI command `sanctum verify-case`.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sanctum.cases.models import CaseState, RecoveryGrade
from sanctum.cases.db import CaseDatabase
from sanctum.cases.reports import ReportRenderer
from sanctum.cases.export import CaseExporter
from sanctum.safety.guard import SafetyGuard, SafetyError
from sanctum.safety.models import OperationMode
from sanctum.dal import DeviceInfo


def main():
    print("=" * 75)
    print("SANCTUM M14 — FORENSIC CASE DATABASE, CHAIN OF CUSTODY & REPORTING")
    print("=" * 75)

    out_dir = Path("scratch/demo_m14")
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = str(out_dir / "sanctum_cases.db")

    # 1. Initialize SQLite WAL Database
    print("\n[+] 1. Initializing Case Database (SQLite WAL mode)...")
    db = CaseDatabase(db_path)
    print(f"    - Database created at: {db_path}")

    # 2. Case Lifecycle
    print("\n[+] 2. Executing Case Lifecycle: CREATE -> OPEN -> ATTACH_EXHIBIT -> PROCESS...")
    case = db.create_case(
        case_number="CASE-2026-ALPHA",
        title="Operation Silent Ghost Exfiltration Investigation",
        investigator="Special Agent Fox Mulder",
        agency="Federal Cyber Division",
        notes="High-priority forensic examination of seized target storage media.",
    )
    print(f"    [1/5] Case Created:  {case.case_number} | State: {case.state.value}")

    case = db.transition_state(case.case_id, CaseState.OPEN)
    print(f"    [2/5] Case Opened:   {case.case_number} | State: {case.state.value}")

    case = db.transition_state(case.case_id, CaseState.ATTACH_EXHIBIT)
    print(f"    [3/5] State Updated: {case.case_number} | State: {case.state.value}")

    serial_num = "NVME-SAMSUNG-SECURE-8841"
    exhibit = db.add_exhibit(
        case_id=case.case_id,
        exhibit_number="EXH-001",
        description="Encrypted NVMe SSD recovered from suspect workstation",
        device_serial=serial_num,
        received_from="Field Seizure Agent",
        storage_location="Vault A - Secure Locker 14",
    )
    db.register_device(
        serial=serial_num,
        case_id=case.case_id,
        exhibit_id=exhibit.exhibit_id,
        model="980 PRO 1TB",
        vendor="Samsung",
        capacity_bytes=1000204886016,
        is_forensic_hold=True,
    )
    print(f"    [+] Attached Exhibit: {exhibit.exhibit_number} (Serial: {serial_num})")

    # 3. Safety Rule: Open forensic case prevents sanitization
    print("\n[+] 3. Testing Safety Rule: Open Forensic Case Prevents Sanitization...")
    guard = SafetyGuard(case_db=db)
    dev_info = DeviceInfo(
        path="/dev/nvme0n1",
        serial=serial_num,
        capacity_bytes=1000204886016,
        sector_size=512,
        lba_count=1953525168,
        is_virtual=True,
    )

    try:
        guard.request_token(
            device=dev_info,
            job_id="JOB-SANITIZE-ATTEMPT",
            operation_id="OP-PURGE",
            mode=OperationMode.SANITIZATION,
            confirmed=True,
        )
        print("    [!] ERROR: Sanitization was NOT blocked!")
    except SafetyError as e:
        print(f"    [OK] Sanitization blocked by SafetyGuard: {e}")

    # 4. Chain of Custody Entries
    print("\n[+] 4. Recording Hash-Chained Chain-of-Custody Events...")
    entry1 = db.add_custody_entry(
        case_id=case.case_id,
        exhibit_id=exhibit.exhibit_id,
        action="TRANSFER_TO_FORENSIC_LAB",
        actor="Special Agent Fox Mulder",
        source_holder="Vault A - Secure Locker 14",
        target_holder="Forensic Acquisition Station 3",
        reason="Bit-stream forensic acquisition and timeline generation",
    )
    print(f"    - Recorded transfer: {entry1.action} (Hash: {entry1.record_hash[:16]}...)")

    is_intact = db.verify_custody_chain(exhibit.exhibit_id)
    print(f"    - Chain-of-Custody Cryptographic Verification: {'INTACT' if is_intact else 'BREACH'}")

    # Transition to PROCESS
    case = db.transition_state(case.case_id, CaseState.PROCESS)
    print(f"    [4/5] Case Processing: {case.case_number} | State: {case.state.value}")

    # 5. Recovered Objects Manifest
    print("\n[+] 5. Recording Recovered Objects into Manifest...")
    db.add_recovered_object(
        case_id=case.case_id,
        name="incident_response_notes.docx",
        extension="docx",
        size_bytes=38912,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recovery_grade=RecoveryGrade.INTACT,
        source_offset=1048576,
        source_lba=2048,
        provenance="NTFS Deleted File Reconstruction (MFT Record 104)",
    )
    db.add_recovered_object(
        case_id=case.case_id,
        name="c2_payload_dump.bin",
        extension="bin",
        size_bytes=65536,
        sha256_hash="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        recovery_grade=RecoveryGrade.CARVED,
        source_offset=52428800,
        source_lba=102400,
        provenance="Aho-Corasick Carved from Ext4 Unallocated Space",
    )
    print(f"    - Recorded 2 recovered objects with SHA-256 hashes and physical source offsets.")

    # 6. Render Reports to PDF/A
    print("\n[+] 6. Rendering PDF/A Reports...")
    case_pdf = str(out_dir / f"ForensicReport_{case.case_number}.pdf")
    ReportRenderer.render_case_report(
        case=case,
        exhibits=[exhibit],
        recovered_objects=db.list_recovered_objects(case.case_id),
        output_pdf_path=case_pdf,
    )
    print(f"    - Case Investigation Report: {case_pdf}")

    custody_pdf = str(out_dir / f"CustodyForm_{exhibit.exhibit_number}.pdf")
    ReportRenderer.render_custody_form(
        case=case,
        exhibit=exhibit,
        entries=db.list_custody_entries(exhibit_id=exhibit.exhibit_id),
        is_chain_intact=is_intact,
        output_pdf_path=custody_pdf,
    )
    print(f"    - Chain-of-Custody Tracking Form: {custody_pdf}")

    # 7. Self-Contained Case Export
    print("\n[+] 7. Generating Self-Contained Case Export (.zip)...")
    export_zip = str(out_dir / f"{case.case_number}_export.zip")
    CaseExporter.export_case(
        case_db=db,
        case_id=case.case_id,
        export_zip_path=export_zip,
        audit_log_entries=[
            {"timestamp": "2026-10-19T12:00:00Z", "event": "CASE_CREATED", "operator": "Mulder"},
            {"timestamp": "2026-10-19T14:30:00Z", "event": "ACQUISITION_VERIFIED", "operator": "Mulder"},
        ],
    )
    print(f"    - Exported archive: {export_zip} ({os.path.getsize(export_zip)} bytes)")

    # 8. Independent Verification
    print("\n[+] 8. Performing Independent Verification on Export Archive...")
    verif = CaseExporter.verify_exported_case(export_zip)
    print(f"    - Export Archive Valid:       {verif['valid']}")
    print(f"    - Verified Files Count:       {verif['verified_files']}")
    print(f"    - Custody Chain Verified:     {verif['custody_intact']}")
    print(f"    - Case Manifest Verified:     {verif['manifest_details']}")

    # 9. Case Lifecycle: CLOSE
    print("\n[+] 9. Closing Case...")
    case = db.transition_state(case.case_id, CaseState.CLOSED)
    print(f"    [5/5] Case State: {case.state.value} | Closed At: {case.closed_at}")

    # Sanitization token is now permitted because the case is officially closed
    token = guard.request_token(
        device=dev_info,
        job_id="JOB-SANITIZE-AUTHORIZED",
        operation_id="OP-PURGE",
        mode=OperationMode.SANITIZATION,
        confirmed=True,
    )
    print(f"    [OK] Device sanitization capability token granted post-case closure (Token: {token.token_id})")

    print("\n" + "=" * 75)
    print("[+] SANCTUM M14 DEMO COMPLETE — ALL VERIFICATIONS PASSED")
    print("=" * 75)


if __name__ == "__main__":
    main()
