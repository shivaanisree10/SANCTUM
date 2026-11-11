import os
import io
import zipfile
import pytest
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sanctum.timeline.models import (
    TimestampType,
    TimestampRecord,
    ExtractedMetadata,
    ForensicTimeline,
)
from sanctum.timeline.timestamps import (
    parse_filetime,
    parse_unix_epoch,
    parse_dos_datetime,
    parse_exif_datetime,
    parse_pdf_date,
    normalize_to_utc,
    convert_timezone,
)
from sanctum.timeline.extractors import (
    extract_exif_and_gps,
    extract_office_properties,
    extract_pdf_metadata,
    extract_id3_metadata,
    extract_alternate_data_stream,
    parse_zone_identifier,
)
from sanctum.timeline.engine import MetadataAndTimelineEngine


def test_filetime_parsing():
    # 2026-10-19 12:00:00 UTC in FILETIME
    # Windows FILETIME is 100-ns intervals since Jan 1, 1601.
    # 2026-10-19 12:00:00 UTC is epoch timestamp 1792411200
    # FILETIME = (1792411200 + 11644473600) * 10_000_000 = 134368848000000000
    ft = 134368848000000000
    rec = parse_filetime(ft, TimestampType.MODIFIED)
    assert rec.raw_value == ft
    assert rec.raw_format == "FILETIME"
    assert rec.normalized_utc == "2026-10-19T12:00:00Z"
    assert not rec.is_local_time


def test_dos_datetime_and_dst():
    # DOS datetime format: 16-bit date, 16-bit time
    # Date: Year - 1980 (7 bits), Month (4 bits), Day (5 bits)
    # 2026-07-15: Year offset = 46 (0b0101110), Month = 7 (0b0111), Day = 15 (0b01111)
    dos_date = (46 << 9) | (7 << 5) | 15
    # Time: Hour (5 bits), Minute (6 bits), Seconds/2 (5 bits)
    # 14:30:10 -> Hour = 14 (0b01110), Minute = 30 (0b011110), Sec/2 = 5 (0b00101)
    dos_time = (14 << 11) | (30 << 5) | 5
    
    rec = parse_dos_datetime(dos_date, dos_time, TimestampType.MODIFIED, local_tz="America/New_York")
    assert rec.is_local_time is True
    # EDT is UTC-4 in July
    # 14:30:10 EDT -> 18:30:10Z
    assert rec.normalized_utc == "2026-07-15T18:30:10Z"
    assert rec.timezone_info == "America/New_York"

    # Winter (EST UTC-5)
    # 2026-01-15 14:30:10 EST -> 19:30:10Z
    dos_date_winter = (46 << 9) | (1 << 5) | 15
    rec_winter = parse_dos_datetime(dos_date_winter, dos_time, TimestampType.MODIFIED, local_tz="America/New_York")
    assert rec_winter.normalized_utc == "2026-01-15T19:30:10Z"

    # Edge cases: Invalid month/day and unknown timezone fallback to 1980-01-01T00:00:00Z
    dos_date_invalid = (46 << 9) | (2 << 5) | 31  # Feb 31
    rec_invalid = parse_dos_datetime(dos_date_invalid, dos_time, TimestampType.MODIFIED, local_tz="America/New_York")
    assert rec_invalid.normalized_utc == "1980-01-01T00:00:00Z"
    assert rec_invalid.is_local_time is True

    # Unknown/invalid timezone name fallback
    rec_bad_tz = parse_dos_datetime(dos_date, dos_time, TimestampType.MODIFIED, local_tz="Invalid/TZ_Name")
    assert rec_bad_tz.normalized_utc == "1980-01-01T00:00:00Z"


def test_ntfs_si_vs_fn_timestomp_detection():
    engine = MetadataAndTimelineEngine()

    # Normal case: $SI and $FN match
    normal_ft = 134368848000000000
    si_norm = {"modified": normal_ft, "created": normal_ft}
    fn_norm = {"modified": normal_ft, "created": normal_ft}
    res_norm = engine.analyze_ntfs_timestamps(si_norm, fn_norm)
    assert res_norm.is_timestomped is False
    assert len(res_norm.timestomp_notes) == 0

    # Timestomped case: $SI modified is backdated before $FN modified
    si_stomped = {"modified": normal_ft - 100_000_000_000, "created": normal_ft}
    fn_stomped = {"modified": normal_ft, "created": normal_ft}
    res_stomped = engine.analyze_ntfs_timestamps(si_stomped, fn_stomped)
    assert res_stomped.is_timestomped is True
    assert any("earlier than $FN" in note for note in res_stomped.timestomp_notes)


def test_pdf_metadata_extraction():
    # Synthetic PDF payload with /Info dictionary
    pdf_data = (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Title (Forensic Examination Report)\n"
        b"   /Author (Special Agent Mulder)\n"
        b"   /CreationDate (D:20261019120000+00'00')\n"
        b"   /Producer (SANCTUM PDF Gen)\n"
        b">>\n"
        b"endobj\n"
        b"%%EOF"
    )
    meta = extract_pdf_metadata(pdf_data)
    assert meta["title"] == "Forensic Examination Report"
    assert meta["author"] == "Special Agent Mulder"
    assert meta["creationdate"] == "D:20261019120000+00'00'"
    assert meta["producer"] == "SANCTUM PDF Gen"

    rec = parse_pdf_date(meta["creationdate"], TimestampType.PDF_CREATED)
    assert rec is not None
    assert rec.normalized_utc == "2026-10-19T12:00:00Z"


def test_office_metadata_extraction():
    # Build in-memory docx / ooxml zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        core_xml = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            b'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            b'<dc:title>Incident Response Plan</dc:title>'
            b'<dc:creator>Security Admin</dc:creator>'
            b'<cp:lastModifiedBy>Examiner</cp:lastModifiedBy>'
            b'<dcterms:created xsi:type="dcterms:W3CDTF">2026-10-18T10:00:00Z</dcterms:created>'
            b'<dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-19T15:30:00Z</dcterms:modified>'
            b'</cp:coreProperties>'
        )
        z.writestr("docProps/core.xml", core_xml)

    props = extract_office_properties(buf.getvalue())
    assert "title" in props, f"props={props}, names={zipfile.ZipFile(buf).namelist()}"
    assert props["title"] == "Incident Response Plan"
    assert props["creator"] == "Security Admin"
    assert props["last_modified_by"] == "Examiner"
    assert props["created"] == "2026-10-18T10:00:00Z"
    assert props["modified"] == "2026-10-19T15:30:00Z"


def test_alternate_data_stream_zone_identifier():
    zone_payload = (
        "[ZoneTransfer]\r\n"
        "ZoneId=3\r\n"
        "ReferrerUrl=https://google.com/search?q=malware\r\n"
        "HostUrl=https://evil-payloads.org/trojan.exe\r\n"
    ).encode("utf-8")
    ads = extract_alternate_data_stream("trojan.exe:Zone.Identifier", zone_payload)
    assert ads.stream_name == "trojan.exe:Zone.Identifier"
    assert ads.zone_identifier is not None
    assert ads.zone_identifier["zoneid"] == "3"
    assert ads.zone_identifier["hosturl"] == "https://evil-payloads.org/trojan.exe"


def test_timeline_generation_and_source_traceability(tmp_path):
    engine = MetadataAndTimelineEngine(case_id="TEST-CASE-M13")

    # Mock extracted metadata
    filetime_1 = 134368848000000000  # 2026-10-19 12:00:00Z
    filetime_2 = 134368948000000000  # Later

    si_set = engine.analyze_ntfs_timestamps(
        {"modified": filetime_2, "created": filetime_1},
        {"modified": filetime_2, "created": filetime_1},
    )

    meta = engine.extract_all_metadata(
        payload=b"dummy file data",
        source_name="evidence_disk.img::Partition1/confidential.docx",
        source_offset=1048576,
        source_lba=2048,
        ntfs_timestamps=si_set,
        ads_streams={
            ":Zone.Identifier": b"[ZoneTransfer]\nZoneId=3\nHostUrl=http://download.com/file\n"
        }
    )

    # Sidecar JSON saving
    sidecar_path = os.path.join(tmp_path, "confidential.docx.meta.json")
    meta.save_sidecar(sidecar_path)
    assert os.path.exists(sidecar_path)

    # Build timeline
    timeline = engine.build_timeline([meta])
    assert len(timeline.events) > 0

    # Verify chronological order
    for i in range(len(timeline.events) - 1):
        assert timeline.events[i].timestamp_utc <= timeline.events[i + 1].timestamp_utc

    # Verify source offset and LBA traceability
    for ev in timeline.events:
        assert ev.source_artefact == "evidence_disk.img::Partition1/confidential.docx"
        assert ev.source_offset == 1048576
        assert ev.source_lba == 2048

    # Export to CSV
    csv_path = os.path.join(tmp_path, "timeline.csv")
    timeline.export_csv(csv_path)
    assert os.path.exists(csv_path)

    with open(csv_path, "r", encoding="utf-8") as f:
        csv_content = f.read()
        assert "SourceOffset" in csv_content
        assert "1048576" in csv_content
        assert "2048" in csv_content
