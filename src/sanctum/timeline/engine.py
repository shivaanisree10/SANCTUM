import uuid
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    TimestampType,
    TimestampRecord,
    NTFSTimestampSet,
    AlternateDataStream,
    ExtractedMetadata,
    TimelineEvent,
    ForensicTimeline,
)
from .timestamps import (
    parse_filetime,
    parse_unix_epoch,
    parse_dos_datetime,
    parse_exif_datetime,
    parse_pdf_date,
    normalize_to_utc,
)
from .extractors import (
    extract_exif_and_gps,
    extract_office_properties,
    extract_pdf_metadata,
    extract_id3_metadata,
    extract_alternate_data_stream,
)


class MetadataAndTimelineEngine:
    """
    Forensic Metadata Extraction and Timeline Engine.
    Handles:
    - Normalization of all timestamps (MACB + embedded) to ISO 8601 UTC.
    - Preservation of separate NTFS $STANDARD_INFORMATION ($SI) and $FILE_NAME ($FN) sets.
    - Timestomp detection ($SI backdated or mismatched with $FN).
    - Extraction of embedded metadata (EXIF/GPS, Office docProps, PDF Info, ID3v1/v2, ADS/Zone.Identifier).
    - Sidecar JSON generation (<filename>.meta.json).
    - Chronological timeline creation with source-offset and LBA traceability.
    """

    def __init__(self, case_id: str = "CASE-2026", evidence_id: str = "EVIDENCE-001"):
        self.case_id = case_id
        self.evidence_id = evidence_id

    def analyze_ntfs_timestamps(
        self,
        si_timestamps: Dict[str, Union[int, datetime]],
        fn_timestamps: Optional[Dict[str, Union[int, datetime]]] = None,
    ) -> NTFSTimestampSet:
        """
        Parses NTFS $STANDARD_INFORMATION ($SI) and $FILE_NAME ($FN) timestamps.
        Detects potential timestomping if:
        1. $SI timestamp is significantly earlier than $FN timestamp (anti-forensic backdating).
        2. $SI nanosecond resolution is zeroed out while $FN is precise.
        """
        parsed_si: Dict[str, TimestampRecord] = {}
        for key, val in si_timestamps.items():
            ts_type = getattr(TimestampType, key.upper(), TimestampType.MODIFIED)
            if isinstance(val, int):
                rec = parse_filetime(val, ts_type)
            elif isinstance(val, datetime):
                rec = normalize_to_utc(val, ts_type, "DATETIME_OBJ")
            else:
                continue
            parsed_si[key.lower()] = rec

        parsed_fn: Dict[str, TimestampRecord] = {}
        if fn_timestamps:
            for key, val in fn_timestamps.items():
                ts_type = getattr(TimestampType, key.upper(), TimestampType.MODIFIED)
                if isinstance(val, int):
                    rec = parse_filetime(val, ts_type)
                elif isinstance(val, datetime):
                    rec = normalize_to_utc(val, ts_type, "DATETIME_OBJ")
                else:
                    continue
                parsed_fn[key.lower()] = rec

        is_timestomped = False
        notes = []

        # Timestomp heuristic:
        # Standard userspace APIs (e.g. SetFileTime) modify $STANDARD_INFORMATION,
        # but the Windows kernel updates $FILE_NAME only on rename/move operations.
        # Thus, if $SI modified/created is earlier than $FN modified/created by a substantial margin (>10s),
        # or if $SI has fractional seconds == 0 while $FN has sub-second precision, flag it!
        if parsed_fn and "modified" in parsed_si and "modified" in parsed_fn:
            si_mod_str = parsed_si["modified"].normalized_utc
            fn_mod_str = parsed_fn["modified"].normalized_utc
            
            # Parse back to datetime for comparison
            dt_si = datetime.fromisoformat(si_mod_str)
            dt_fn = datetime.fromisoformat(fn_mod_str)
            
            if dt_si < dt_fn:
                is_timestomped = True
                notes.append(f"$SI modified ({si_mod_str}) is earlier than $FN modified ({fn_mod_str})")

            # Check sub-second zeroing
            if isinstance(parsed_si["modified"].raw_value, int) and isinstance(parsed_fn["modified"].raw_value, int):
                si_ft = parsed_si["modified"].raw_value
                fn_ft = parsed_fn["modified"].raw_value
                if (si_ft % 10_000_000 == 0) and (fn_ft % 10_000_000 != 0):
                    is_timestomped = True
                    notes.append("Sub-second resolution in $SI is zeroed out while $FN retains sub-second precision.")

        if parsed_fn and "created" in parsed_si and "created" in parsed_fn:
            dt_si_cr = datetime.fromisoformat(parsed_si["created"].normalized_utc)
            dt_fn_cr = datetime.fromisoformat(parsed_fn["created"].normalized_utc)
            if dt_si_cr < dt_fn_cr:
                is_timestomped = True
                notes.append(f"$SI created ({parsed_si['created'].normalized_utc}) is earlier than $FN created ({parsed_fn['created'].normalized_utc})")

        return NTFSTimestampSet(
            standard_info=parsed_si,
            file_name=parsed_fn,
            is_timestomped=is_timestomped,
            timestomp_notes=notes,
        )

    def extract_all_metadata(
        self,
        payload: bytes,
        source_name: str,
        source_offset: int = 0,
        source_lba: int = 0,
        filesystem_timestamps: Optional[List[TimestampRecord]] = None,
        ntfs_timestamps: Optional[NTFSTimestampSet] = None,
        ads_streams: Optional[Dict[str, bytes]] = None,
    ) -> ExtractedMetadata:
        """
        Extracts all embedded metadata and combines with filesystem & NTFS timestamps.
        """
        exif_info, gps_info = extract_exif_and_gps(payload)
        office_info = extract_office_properties(payload)
        pdf_info = extract_pdf_metadata(payload)
        id3_info = extract_id3_metadata(payload)

        ads_list: List[AlternateDataStream] = []
        if ads_streams:
            for sname, sbytes in ads_streams.items():
                ads_list.append(extract_alternate_data_stream(sname, sbytes))

        artefact_id = str(uuid.uuid4())[:8]

        metadata = ExtractedMetadata(
            artefact_id=artefact_id,
            artefact_name=source_name,
            source_path=source_name,
            source_offset_bytes=source_offset,
            source_lba=source_lba,
            ntfs_timestamps=ntfs_timestamps,
            filesystem_timestamps=filesystem_timestamps or [],
            exif=exif_info,
            gps=gps_info,
            office_properties=office_info,
            pdf_metadata=pdf_info,
            id3=id3_info,
            alternate_data_streams=ads_list,
        )
        return metadata

    def build_timeline(self, metadata_list: List[ExtractedMetadata]) -> ForensicTimeline:
        """
        Flattens all timestamps from all extracted metadata objects into a unified,
        chronologically sorted forensic timeline.
        Every event retains its source artifact, offset, LBA, and timestamp type.
        """
        timeline = ForensicTimeline(case_id=self.case_id, evidence_id=self.evidence_id)

        for meta in metadata_list:
            # 1. Process NTFS timestamps
            if meta.ntfs_timestamps:
                # $SI
                for k, ts_rec in meta.ntfs_timestamps.standard_info.items():
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=ts_rec.normalized_utc,
                            timestamp_type=f"NTFS_$SI_{k.upper()}",
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"NTFS $STANDARD_INFORMATION {k} timestamp ({ts_rec.raw_format})",
                            details={"raw_value": str(ts_rec.raw_value), "timestomped": meta.ntfs_timestamps.is_timestomped},
                        )
                    )
                # $FN
                for k, ts_rec in meta.ntfs_timestamps.file_name.items():
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=ts_rec.normalized_utc,
                            timestamp_type=f"NTFS_$FN_{k.upper()}",
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"NTFS $FILE_NAME {k} timestamp ({ts_rec.raw_format})",
                            details={"raw_value": str(ts_rec.raw_value)},
                        )
                    )

            # 2. General filesystem timestamps (e.g. FAT, ext4, HFS+)
            for fs_rec in meta.filesystem_timestamps:
                timeline.events.append(
                    TimelineEvent(
                        event_id=str(uuid.uuid4())[:8],
                        timestamp_utc=fs_rec.normalized_utc,
                        timestamp_type=f"FS_{fs_rec.ts_type.value}",
                        source_artefact=meta.artefact_name,
                        source_offset=meta.source_offset_bytes,
                        source_lba=meta.source_lba,
                        description=f"Filesystem {fs_rec.ts_type.value} timestamp (Local: {fs_rec.is_local_time})",
                        details={"raw_value": str(fs_rec.raw_value), "raw_format": fs_rec.raw_format},
                    )
                )

            # 3. EXIF timestamps
            if "datetime_original" in meta.exif:
                ts_rec = parse_exif_datetime(meta.exif["datetime_original"], TimestampType.EXIF_TAKEN)
                if ts_rec:
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=ts_rec.normalized_utc,
                            timestamp_type=ts_rec.ts_type.value,
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"EXIF Photo Taken Date ({meta.exif.get('make', '')} {meta.exif.get('model', '')})",
                            details=meta.exif,
                        )
                    )

            # 4. Office properties
            if "created" in meta.office_properties:
                try:
                    dt = datetime.fromisoformat(meta.office_properties["created"].replace("Z", "+00:00"))
                    ts_rec = normalize_to_utc(dt, TimestampType.OFFICE_CREATED, "OOXML_DATE")
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=ts_rec.normalized_utc,
                            timestamp_type=ts_rec.ts_type.value,
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"Office Document Created (Author: {meta.office_properties.get('creator', 'Unknown')})",
                            details=meta.office_properties,
                        )
                    )
                except Exception:
                    pass

            if "modified" in meta.office_properties:
                try:
                    dt = datetime.fromisoformat(meta.office_properties["modified"].replace("Z", "+00:00"))
                    ts_rec = normalize_to_utc(dt, TimestampType.OFFICE_MODIFIED, "OOXML_DATE")
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=ts_rec.normalized_utc,
                            timestamp_type=ts_rec.ts_type.value,
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"Office Document Modified (Last modified by: {meta.office_properties.get('last_modified_by', 'Unknown')})",
                            details=meta.office_properties,
                        )
                    )
                except Exception:
                    pass

            # 5. PDF metadata
            if "creationdate" in meta.pdf_metadata:
                ts_rec = parse_pdf_date(meta.pdf_metadata["creationdate"], TimestampType.PDF_CREATED)
                if ts_rec:
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=ts_rec.normalized_utc,
                            timestamp_type=ts_rec.ts_type.value,
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"PDF Created (Producer: {meta.pdf_metadata.get('producer', 'Unknown')})",
                            details=meta.pdf_metadata,
                        )
                    )

            if "moddate" in meta.pdf_metadata:
                ts_rec = parse_pdf_date(meta.pdf_metadata["moddate"], TimestampType.PDF_MODIFIED)
                if ts_rec:
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=ts_rec.normalized_utc,
                            timestamp_type=ts_rec.ts_type.value,
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"PDF Modified (Author: {meta.pdf_metadata.get('author', 'Unknown')})",
                            details=meta.pdf_metadata,
                        )
                    )

            # 6. ID3 metadata
            if "year" in meta.id3:
                year_str = str(meta.id3["year"])[:4]
                if year_str.isdigit() and len(year_str) == 4:
                    dt = datetime(int(year_str), 1, 1, 0, 0, 0, tzinfo=timezone.utc)
                    ts_rec = normalize_to_utc(dt, TimestampType.ID3_RELEASE, "ID3_YEAR")
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=ts_rec.normalized_utc,
                            timestamp_type=ts_rec.ts_type.value,
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"ID3 Track Release Year ({meta.id3.get('artist', '')} - {meta.id3.get('title', '')})",
                            details=meta.id3,
                        )
                    )

            # 7. ADS / Zone.Identifier
            for ads in meta.alternate_data_streams:
                if ads.zone_identifier and "hosturl" in ads.zone_identifier:
                    timeline.events.append(
                        TimelineEvent(
                            event_id=str(uuid.uuid4())[:8],
                            timestamp_utc=datetime.now(timezone.utc).isoformat(),
                            timestamp_type=TimestampType.ZONE_DOWNLOAD.value,
                            source_artefact=meta.artefact_name,
                            source_offset=meta.source_offset_bytes,
                            source_lba=meta.source_lba,
                            description=f"Web Download Zone.Identifier (ZoneId={ads.zone_identifier.get('zoneid')})",
                            details=ads.zone_identifier,
                        )
                    )

        timeline.sort_events()
        return timeline
