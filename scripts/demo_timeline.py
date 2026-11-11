#!/usr/bin/env python3
"""
M13 Demonstration Script — Metadata Extraction and Unified Forensic Timeline.
Demonstrates:
- Timestamp extraction & UTC normalization (FILETIME, Unix epoch, FAT DOS date/time).
- Timestomp detection ($STANDARD_INFORMATION vs $FILE_NAME).
- Embedded metadata extraction (EXIF, GPS coordinates, Office docProps, PDF info, ID3, Zone.Identifier).
- Sidecar JSON generation (<artefact>.meta.json).
- Unified chronological timeline export to CSV and JSON with source-offset provenance.
"""

import sys
import os
import io
import zipfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sanctum.timeline.models import TimestampType
from sanctum.timeline.timestamps import parse_filetime, parse_dos_datetime, parse_unix_epoch
from sanctum.timeline.engine import MetadataAndTimelineEngine
from sanctum.timeline.extractors import extract_alternate_data_stream


def main():
    print("=" * 70)
    print("SANCTUM M13 — FORENSIC METADATA EXTRACTION & UNIFIED TIMELINE ENGINE")
    print("=" * 70)

    engine = MetadataAndTimelineEngine(case_id="CASE-2026-INCIDENT", evidence_id="ITEM-EVIDENCE-01")

    # 1. Timestomp Detection Demo
    print("\n[+] 1. Demonstrating NTFS Timestomp Detection ($SI vs $FN)...")
    normal_mtime = 134368848000000000   # 2026-10-19 12:00:00Z
    backdated_mtime = 129000000000000000 # Backdated into the past
    
    si_set = engine.analyze_ntfs_timestamps(
        si_timestamps={"modified": backdated_mtime, "created": backdated_mtime},
        fn_timestamps={"modified": normal_mtime, "created": normal_mtime},
    )
    print(f"    - Timestomped detected: {si_set.is_timestomped}")
    for note in si_set.timestomp_notes:
        print(f"      [!] Alert: {note}")

    # 2. Extract embedded Office document metadata
    print("\n[+] 2. Parsing Embedded Office Open XML Document Metadata...")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        core_xml = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            b'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            b'<dc:title>Exfiltration Strategy Q3</dc:title>'
            b'<dc:creator>Threat Actor</dc:creator>'
            b'<cp:lastModifiedBy>Operator-42</cp:lastModifiedBy>'
            b'<dcterms:created xsi:type="dcterms:W3CDTF">2026-09-01T08:15:00Z</dcterms:created>'
            b'<dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-18T23:59:00Z</dcterms:modified>'
            b'</cp:coreProperties>'
        )
        z.writestr("docProps/core.xml", core_xml)
    doc_payload = buf.getvalue()

    # Zone.Identifier ADS
    zone_data = (
        b"[ZoneTransfer]\r\n"
        b"ZoneId=3\r\n"
        b"HostUrl=https://attacker-c2.net/payloads/ExfiltrationStrategy.docx\r\n"
        b"ReferrerUrl=https://phishing-portal.com/login\r\n"
    )

    meta = engine.extract_all_metadata(
        payload=doc_payload,
        source_name="evidence.dd::Partition2/Users/Target/Downloads/ExfiltrationStrategy.docx",
        source_offset=20971520,
        source_lba=40960,
        ntfs_timestamps=si_set,
        ads_streams={"Zone.Identifier": zone_data},
    )

    print(f"    - Extracted Document Title: {meta.office_properties.get('title')}")
    print(f"    - Author/Creator: {meta.office_properties.get('creator')}")
    print(f"    - ADS ZoneId: {meta.alternate_data_streams[0].zone_identifier.get('zoneid')}")
    print(f"    - Origin HostUrl: {meta.alternate_data_streams[0].zone_identifier.get('hosturl')}")

    # 3. Sidecar JSON Generation
    out_dir = Path("scratch")
    out_dir.mkdir(parents=True, exist_ok=True)
    sidecar_path = out_dir / "ExfiltrationStrategy.docx.meta.json"
    meta.save_sidecar(str(sidecar_path))
    print(f"\n[+] 3. Stored Sidecar Forensic Metadata Manifest at: {sidecar_path}")

    # 4. Build Forensic Timeline
    print("\n[+] 4. Building Unified Chronological Forensic Timeline...")
    timeline = engine.build_timeline([meta])
    csv_path = out_dir / "forensic_timeline.csv"
    json_path = out_dir / "forensic_timeline.json"
    timeline.export_csv(str(csv_path))
    timeline.export_json(str(json_path))

    print(f"    - Total Timeline Events: {len(timeline.events)}")
    print(f"    - Exported CSV Timeline to: {csv_path}")
    print(f"    - Exported JSON Timeline to: {json_path}")
    print("\n[+] Timeline Chronological Events:")
    for ev in timeline.events:
        print(f"    [{ev.timestamp_utc}] Type: {ev.timestamp_type:<22} Offset: {ev.source_offset:<10} | {ev.description}")

    print("\n[+] M13 Demo completed successfully with zero source modifications.")


if __name__ == "__main__":
    main()
