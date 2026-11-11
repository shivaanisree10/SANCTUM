import os
import json
import zipfile
import hashlib
from typing import Dict, Any, List, Optional
from pathlib import Path

from .db import CaseDatabase
from .models import CaseRecord, ExhibitRecord, RecoveredObjectRecord
from .reports import ReportRenderer


class CaseExporter:
    """
    Creates and verifies self-contained forensic case export packages:
    - manifest.json: Metadata, exhibits, recovered object provenance, SHA-256 hashes
    - reports/: Rendered forensic case reports, custody forms, destruction certificates
    - audit/: Relevant cryptographically chained audit logs
    - hashes.sha256: Complete cryptographic integrity manifest
    """

    @classmethod
    def export_case(
        cls,
        case_db: CaseDatabase,
        case_id: str,
        export_zip_path: str,
        audit_log_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        case = case_db.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found.")

        exhibits = []
        cur = case_db._conn.cursor()
        cur.execute("SELECT * FROM exhibits WHERE case_id = ?", (case.case_id,))
        for r in cur.fetchall():
            exhibits.append(
                ExhibitRecord(
                    exhibit_id=r["exhibit_id"],
                    case_id=r["case_id"],
                    exhibit_number=r["exhibit_number"],
                    description=r["description"],
                    device_serial=r["device_serial"],
                    received_from=r["received_from"],
                    received_at=r["received_at"],
                    storage_location=r["storage_location"],
                    status=r["status"],
                )
            )

        recovered_objs = case_db.list_recovered_objects(case.case_id)
        custody_entries = case_db.list_custody_entries(case_id=case.case_id)

        # Build manifest dictionary
        manifest = {
            "sanctum_version": "0.1.0",
            "case": case.model_dump(),
            "exhibits": [e.model_dump() for e in exhibits],
            "recovered_objects_count": len(recovered_objs),
            "recovered_objects": [o.model_dump() for o in recovered_objs],
            "custody_chain_verified": all(case_db.verify_custody_chain(e.exhibit_id) for e in exhibits) if exhibits else True,
            "custody_entries": [c.model_dump() for c in custody_entries],
        }

        # Build in-memory or temporary files for zip packaging
        temp_dir = Path(export_zip_path).parent / f"export_{case.case_number}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        reports_dir = temp_dir / "reports"
        audit_dir = temp_dir / "audit"
        reports_dir.mkdir(parents=True, exist_ok=True)
        audit_dir.mkdir(parents=True, exist_ok=True)

        # 1. Manifest
        manifest_file = temp_dir / "manifest.json"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        # 2. Case Report PDF
        case_report_pdf = reports_dir / f"CaseReport_{case.case_number}.pdf"
        ReportRenderer.render_case_report(case, exhibits, recovered_objs, str(case_report_pdf))

        # 3. Chain of Custody PDFs
        for exh in exhibits:
            exh_custody = [c for c in custody_entries if c.exhibit_id == exh.exhibit_id]
            is_intact = case_db.verify_custody_chain(exh.exhibit_id)
            custody_pdf = reports_dir / f"CustodyForm_{exh.exhibit_number}.pdf"
            ReportRenderer.render_custody_form(case, exh, exh_custody, is_intact, str(custody_pdf))

        # 4. Audit logs
        audit_file = audit_dir / "audit_log.json"
        with open(audit_file, "w", encoding="utf-8") as f:
            json.dump(audit_log_entries or [], f, indent=2)

        # 5. Cryptographic hash list
        file_hashes: Dict[str, str] = {}
        for root, _, files in os.walk(temp_dir):
            for file in sorted(files):
                fpath = Path(root) / file
                rel_path = fpath.relative_to(temp_dir).as_posix()
                with open(fpath, "rb") as f:
                    file_hashes[rel_path] = hashlib.sha256(f.read()).hexdigest()

        hash_list_path = temp_dir / "hashes.sha256"
        with open(hash_list_path, "w", encoding="utf-8") as f:
            for rel, h in sorted(file_hashes.items()):
                f.write(f"{h}  {rel}\n")

        # 6. Package into self-contained zip
        with zipfile.ZipFile(export_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    fp = Path(root) / file
                    arcname = fp.relative_to(temp_dir).as_posix()
                    zf.write(fp, arcname)

        # Clean temporary directory
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

        return manifest

    @classmethod
    def verify_exported_case(cls, export_zip_path: str) -> Dict[str, Any]:
        """
        Independent verification tool for exported forensic cases:
        1. Verifies hashes.sha256 against every file inside the zip archive.
        2. Validates manifest structure and recovered object count.
        3. Verifies cryptographic integrity of the internal chain-of-custody hashes.
        """
        results: Dict[str, Any] = {
            "valid": True,
            "corrupted_files": [],
            "verified_files": 0,
            "custody_intact": True,
            "manifest_details": {},
            "errors": [],
        }

        if not os.path.exists(export_zip_path):
            results["valid"] = False
            results["errors"].append(f"Export archive {export_zip_path} does not exist.")
            return results

        try:
            with zipfile.ZipFile(export_zip_path, "r") as zf:
                namelist = zf.namelist()
                if "hashes.sha256" not in namelist or "manifest.json" not in namelist:
                    results["valid"] = False
                    results["errors"].append("Missing required hashes.sha256 or manifest.json in export archive.")
                    return results

                # Read hashes.sha256
                hash_content = zf.read("hashes.sha256").decode("utf-8")
                expected_hashes: Dict[str, str] = {}
                for line in hash_content.strip().splitlines():
                    if "  " in line:
                        h, fname = line.split("  ", 1)
                        expected_hashes[fname.strip()] = h.strip()

                # Verify each file
                for fname, expected_hash in expected_hashes.items():
                    if fname == "hashes.sha256":
                        continue
                    if fname not in namelist:
                        results["valid"] = False
                        results["corrupted_files"].append(fname)
                        results["errors"].append(f"File {fname} declared in manifest is missing in archive.")
                        continue

                    data = zf.read(fname)
                    calc_hash = hashlib.sha256(data).hexdigest()
                    if calc_hash != expected_hash:
                        results["valid"] = False
                        results["corrupted_files"].append(fname)
                        results["errors"].append(f"Hash mismatch for {fname}: expected {expected_hash}, calculated {calc_hash}")
                    else:
                        results["verified_files"] += 1

                # Parse manifest.json and verify chain of custody
                manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
                results["manifest_details"] = {
                    "case_number": manifest_data.get("case", {}).get("case_number"),
                    "title": manifest_data.get("case", {}).get("title"),
                    "recovered_objects": manifest_data.get("recovered_objects_count", 0),
                    "exhibits": len(manifest_data.get("exhibits", [])),
                }

                custody_entries = manifest_data.get("custody_entries", [])
                # Group by exhibit
                by_exhibit: Dict[str, List[Dict[str, Any]]] = {}
                for ce in custody_entries:
                    by_exhibit.setdefault(ce["exhibit_id"], []).append(ce)

                for exh_id, entries in by_exhibit.items():
                    # Sort by timestamp
                    entries.sort(key=lambda x: x["timestamp_utc"])
                    expected_prev = "0" * 64
                    for e in entries:
                        if e["prev_record_hash"] != expected_prev:
                            results["custody_intact"] = False
                            results["valid"] = False
                            results["errors"].append(f"Chain of custody breach in exhibit {exh_id}: invalid prev_record_hash.")
                            break
                        payload = (
                            f"{e['entry_id']}|{e['case_id']}|{e['exhibit_id']}|{e['timestamp_utc']}|"
                            f"{e['action']}|{e['actor']}|{e['source_holder']}|{e['target_holder']}|"
                            f"{e['reason']}|{e['prev_record_hash']}"
                        )
                        calc_h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                        if calc_h != e["record_hash"]:
                            results["custody_intact"] = False
                            results["valid"] = False
                            results["errors"].append(f"Chain of custody breach in exhibit {exh_id}: invalid record_hash.")
                            break
                        expected_prev = e["record_hash"]

        except Exception as e:
            results["valid"] = False
            results["errors"].append(f"Verification exception: {str(e)}")

        return results
