import sqlite3
import hashlib
import json
import uuid
import datetime
from typing import List, Optional, Dict, Any

from .models import (
    CaseState,
    RecoveryGrade,
    CaseRecord,
    ExhibitRecord,
    DeviceRecord,
    JobRecord,
    ImageRecord,
    RecoveredObjectRecord,
    CustodyEntryRecord,
    CertificateRecord,
)
from sanctum.exceptions import SanctumError


class CaseDatabaseError(SanctumError):
    """Raised on database schema or operational errors."""
    pass


class CaseLifecycleError(SanctumError):
    """Raised on invalid lifecycle transitions."""
    pass


SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_number TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    investigator TEXT NOT NULL,
    agency TEXT,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    closed_at TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS exhibits (
    exhibit_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    exhibit_number TEXT NOT NULL,
    description TEXT NOT NULL,
    device_serial TEXT,
    received_from TEXT,
    received_at TEXT NOT NULL,
    storage_location TEXT,
    status TEXT NOT NULL,
    UNIQUE(case_id, exhibit_number)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(case_id) ON DELETE SET NULL,
    exhibit_id TEXT REFERENCES exhibits(exhibit_id) ON DELETE SET NULL,
    serial TEXT UNIQUE NOT NULL,
    model TEXT,
    vendor TEXT,
    capacity_bytes INTEGER DEFAULT 0,
    wwn TEXT,
    interface TEXT,
    is_forensic_hold INTEGER DEFAULT 1,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    device_serial TEXT,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    parameters TEXT,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS images (
    image_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    exhibit_id TEXT REFERENCES exhibits(exhibit_id) ON DELETE SET NULL,
    format TEXT NOT NULL,
    file_path TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    sha256_hash TEXT NOT NULL,
    source_serial TEXT NOT NULL,
    segment_count INTEGER DEFAULT 1,
    acquired_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovered_objects (
    object_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    exhibit_id TEXT REFERENCES exhibits(exhibit_id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    extension TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256_hash TEXT NOT NULL,
    recovery_grade TEXT NOT NULL,
    source_offset INTEGER NOT NULL,
    source_lba INTEGER DEFAULT 0,
    provenance TEXT NOT NULL,
    metadata_json TEXT,
    recovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS custody_entries (
    entry_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    exhibit_id TEXT NOT NULL REFERENCES exhibits(exhibit_id) ON DELETE CASCADE,
    timestamp_utc TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    source_holder TEXT NOT NULL,
    target_holder TEXT NOT NULL,
    reason TEXT NOT NULL,
    prev_record_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
    certificate_id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(case_id) ON DELETE SET NULL,
    certificate_type TEXT NOT NULL,
    device_serial TEXT NOT NULL,
    result TEXT NOT NULL,
    method TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
"""


class CaseDatabase:
    """
    Forensic Case Database backed by SQLite with WAL mode.
    Manages cases, exhibits, devices, jobs, forensic images, recovered objects,
    tamper-evident hash-chained custody entries, and certificates.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.executescript(SCHEMA_SQL)

    def close(self) -> None:
        self._conn.close()

    # -------------------------------------------------------------------------
    # Case Lifecycle: CREATE -> OPEN -> ATTACH_EXHIBIT -> PROCESS -> CLOSE
    # -------------------------------------------------------------------------

    def create_case(
        self,
        case_number: str,
        title: str,
        investigator: str,
        agency: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> CaseRecord:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        record = CaseRecord(
            case_id=case_id,
            case_number=case_number,
            title=title,
            investigator=investigator,
            agency=agency,
            state=CaseState.CREATED,
            notes=notes,
        )
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO cases (case_id, case_number, title, investigator, agency, state, created_at, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.case_id,
                    record.case_number,
                    record.title,
                    record.investigator,
                    record.agency,
                    record.state.value,
                    record.created_at,
                    record.notes,
                ),
            )
        return record

    def transition_state(self, case_id: str, new_state: CaseState) -> CaseRecord:
        case = self.get_case(case_id)
        if not case:
            raise CaseDatabaseError(f"Case {case_id} not found.")

        # Valid transitions:
        # CREATED -> OPEN
        # OPEN -> ATTACH_EXHIBIT
        # ATTACH_EXHIBIT -> PROCESS
        # PROCESS -> ATTACH_EXHIBIT (allowing more exhibits)
        # PROCESS -> CLOSED
        valid_transitions = {
            CaseState.CREATED: [CaseState.OPEN],
            CaseState.OPEN: [CaseState.ATTACH_EXHIBIT],
            CaseState.ATTACH_EXHIBIT: [CaseState.PROCESS],
            CaseState.PROCESS: [CaseState.ATTACH_EXHIBIT, CaseState.CLOSED],
            CaseState.CLOSED: [],
        }

        if new_state not in valid_transitions.get(case.state, []):
            raise CaseLifecycleError(
                f"Invalid lifecycle transition for case {case_id} from {case.state.value} to {new_state.value}."
            )

        closed_at = datetime.datetime.now(datetime.timezone.utc).isoformat() if new_state == CaseState.CLOSED else None

        with self._conn:
            self._conn.execute(
                "UPDATE cases SET state = ?, closed_at = ? WHERE case_id = ?",
                (new_state.value, closed_at, case_id),
            )

        return self.get_case(case_id)

    def get_case(self, case_id: str) -> Optional[CaseRecord]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM cases WHERE case_id = ? OR case_number = ?", (case_id, case_id))
        row = cur.fetchone()
        if not row:
            return None
        return CaseRecord(
            case_id=row["case_id"],
            case_number=row["case_number"],
            title=row["title"],
            investigator=row["investigator"],
            agency=row["agency"],
            state=CaseState(row["state"]),
            created_at=row["created_at"],
            closed_at=row["closed_at"],
            notes=row["notes"],
        )

    def list_cases(self) -> List[CaseRecord]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM cases ORDER BY created_at DESC")
        cases = []
        for row in cur.fetchall():
            cases.append(
                CaseRecord(
                    case_id=row["case_id"],
                    case_number=row["case_number"],
                    title=row["title"],
                    investigator=row["investigator"],
                    agency=row["agency"],
                    state=CaseState(row["state"]),
                    created_at=row["created_at"],
                    closed_at=row["closed_at"],
                    notes=row["notes"],
                )
            )
        return cases

    # -------------------------------------------------------------------------
    # Exhibits and Devices
    # -------------------------------------------------------------------------

    def add_exhibit(
        self,
        case_id: str,
        exhibit_number: str,
        description: str,
        device_serial: Optional[str] = None,
        received_from: Optional[str] = None,
        storage_location: Optional[str] = None,
    ) -> ExhibitRecord:
        case = self.get_case(case_id)
        if not case:
            raise CaseDatabaseError(f"Case {case_id} not found.")
        if case.state == CaseState.CLOSED:
            raise CaseLifecycleError("Cannot attach exhibits to a CLOSED case.")

        exhibit_id = f"EXH-{uuid.uuid4().hex[:8].upper()}"
        record = ExhibitRecord(
            exhibit_id=exhibit_id,
            case_id=case.case_id,
            exhibit_number=exhibit_number,
            description=description,
            device_serial=device_serial,
            received_from=received_from,
            storage_location=storage_location,
        )

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO exhibits (exhibit_id, case_id, exhibit_number, description, device_serial, received_from, received_at, storage_location, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.exhibit_id,
                    record.case_id,
                    record.exhibit_number,
                    record.description,
                    record.device_serial,
                    record.received_from,
                    record.received_at,
                    record.storage_location,
                    record.status,
                ),
            )

        # Automatically record initial seizure / custody entry
        self.add_custody_entry(
            case_id=case.case_id,
            exhibit_id=record.exhibit_id,
            action="SEIZED_AND_BOOKED",
            actor=case.investigator,
            source_holder=received_from or "Field Evidentiary Source",
            target_holder=storage_location or "Evidence Locker",
            reason="Initial evidence intake into custody",
        )

        return record

    def register_device(
        self,
        serial: str,
        case_id: Optional[str] = None,
        exhibit_id: Optional[str] = None,
        model: Optional[str] = None,
        vendor: Optional[str] = None,
        capacity_bytes: int = 0,
        wwn: Optional[str] = None,
        interface: Optional[str] = None,
        is_forensic_hold: bool = True,
    ) -> DeviceRecord:
        dev_id = f"DEV-{uuid.uuid4().hex[:8].upper()}"
        record = DeviceRecord(
            device_id=dev_id,
            case_id=case_id,
            exhibit_id=exhibit_id,
            serial=serial,
            model=model,
            vendor=vendor,
            capacity_bytes=capacity_bytes,
            wwn=wwn,
            interface=interface,
            is_forensic_hold=is_forensic_hold,
        )

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO devices (device_id, case_id, exhibit_id, serial, model, vendor, capacity_bytes, wwn, interface, is_forensic_hold, added_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(serial) DO UPDATE SET
                    case_id=excluded.case_id,
                    exhibit_id=excluded.exhibit_id,
                    is_forensic_hold=excluded.is_forensic_hold
                """,
                (
                    record.device_id,
                    record.case_id,
                    record.exhibit_id,
                    record.serial,
                    record.model,
                    record.vendor,
                    record.capacity_bytes,
                    record.wwn,
                    record.interface,
                    1 if record.is_forensic_hold else 0,
                    record.added_at,
                ),
            )
        return record

    def is_device_in_forensic_case(self, serial: str) -> bool:
        """
        Safety Guard check: An open forensic case attached to a device must prevent sanitization.
        Returns True if device is attached to an open (non-CLOSED) forensic case or has forensic hold set.
        """
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT d.is_forensic_hold, c.state
            FROM devices d
            LEFT JOIN cases c ON d.case_id = c.case_id
            WHERE d.serial = ?
            """,
            (serial,),
        )
        row = cur.fetchone()
        if not row:
            return False

        is_hold = bool(row["is_forensic_hold"])
        case_state = row["state"]

        if is_hold and case_state and case_state != CaseState.CLOSED.value:
            return True
        return False

    # -------------------------------------------------------------------------
    # Chain of Custody (Tamper-Evident SHA-256 Chaining)
    # -------------------------------------------------------------------------

    def get_latest_custody_hash(self, exhibit_id: str) -> str:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT record_hash FROM custody_entries WHERE exhibit_id = ? ORDER BY timestamp_utc DESC LIMIT 1",
            (exhibit_id,),
        )
        row = cur.fetchone()
        if row:
            return row["record_hash"]
        return "0" * 64

    def add_custody_entry(
        self,
        case_id: str,
        exhibit_id: str,
        action: str,
        actor: str,
        source_holder: str,
        target_holder: str,
        reason: str,
        notes: Optional[str] = None,
    ) -> CustodyEntryRecord:
        prev_hash = self.get_latest_custody_hash(exhibit_id)
        entry_id = f"COC-{uuid.uuid4().hex[:8].upper()}"
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Build tamper-evident hash
        hash_payload = f"{entry_id}|{case_id}|{exhibit_id}|{ts}|{action}|{actor}|{source_holder}|{target_holder}|{reason}|{prev_hash}"
        record_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        record = CustodyEntryRecord(
            entry_id=entry_id,
            case_id=case_id,
            exhibit_id=exhibit_id,
            timestamp_utc=ts,
            action=action,
            actor=actor,
            source_holder=source_holder,
            target_holder=target_holder,
            reason=reason,
            prev_record_hash=prev_hash,
            record_hash=record_hash,
            notes=notes,
        )

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO custody_entries (
                    entry_id, case_id, exhibit_id, timestamp_utc, action, actor,
                    source_holder, target_holder, reason, prev_record_hash, record_hash, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.entry_id,
                    record.case_id,
                    record.exhibit_id,
                    record.timestamp_utc,
                    record.action,
                    record.actor,
                    record.source_holder,
                    record.target_holder,
                    record.reason,
                    record.prev_record_hash,
                    record.record_hash,
                    record.notes,
                ),
            )
        return record

    def verify_custody_chain(self, exhibit_id: str) -> bool:
        """Verifies the integrity of the hash-linked chain-of-custody ledger."""
        cur = self._conn.cursor()
        cur.execute(
            "SELECT * FROM custody_entries WHERE exhibit_id = ? ORDER BY timestamp_utc ASC",
            (exhibit_id,),
        )
        rows = cur.fetchall()
        expected_prev = "0" * 64

        for r in rows:
            if r["prev_record_hash"] != expected_prev:
                return False
            payload = (
                f"{r['entry_id']}|{r['case_id']}|{r['exhibit_id']}|{r['timestamp_utc']}|"
                f"{r['action']}|{r['actor']}|{r['source_holder']}|{r['target_holder']}|"
                f"{r['reason']}|{r['prev_record_hash']}"
            )
            calc_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if calc_hash != r["record_hash"]:
                return False
            expected_prev = r["record_hash"]

        return True

    def list_custody_entries(self, exhibit_id: Optional[str] = None, case_id: Optional[str] = None) -> List[CustodyEntryRecord]:
        cur = self._conn.cursor()
        if exhibit_id:
            cur.execute("SELECT * FROM custody_entries WHERE exhibit_id = ? ORDER BY timestamp_utc ASC", (exhibit_id,))
        elif case_id:
            cur.execute("SELECT * FROM custody_entries WHERE case_id = ? ORDER BY timestamp_utc ASC", (case_id,))
        else:
            cur.execute("SELECT * FROM custody_entries ORDER BY timestamp_utc ASC")

        entries = []
        for r in cur.fetchall():
            entries.append(
                CustodyEntryRecord(
                    entry_id=r["entry_id"],
                    case_id=r["case_id"],
                    exhibit_id=r["exhibit_id"],
                    timestamp_utc=r["timestamp_utc"],
                    action=r["action"],
                    actor=r["actor"],
                    source_holder=r["source_holder"],
                    target_holder=r["target_holder"],
                    reason=r["reason"],
                    prev_record_hash=r["prev_record_hash"],
                    record_hash=r["record_hash"],
                    notes=r["notes"],
                )
            )
        return entries

    # -------------------------------------------------------------------------
    # Recovered Objects Manifest
    # -------------------------------------------------------------------------

    def add_recovered_object(
        self,
        case_id: str,
        name: str,
        extension: str,
        size_bytes: int,
        sha256_hash: str,
        recovery_grade: RecoveryGrade,
        source_offset: int,
        provenance: str,
        source_lba: int = 0,
        exhibit_id: Optional[str] = None,
        metadata_json: Optional[str] = None,
    ) -> RecoveredObjectRecord:
        obj_id = f"OBJ-{uuid.uuid4().hex[:8].upper()}"
        record = RecoveredObjectRecord(
            object_id=obj_id,
            case_id=case_id,
            exhibit_id=exhibit_id,
            name=name,
            extension=extension,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            recovery_grade=recovery_grade,
            source_offset=source_offset,
            source_lba=source_lba,
            provenance=provenance,
            metadata_json=metadata_json,
        )

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO recovered_objects (
                    object_id, case_id, exhibit_id, name, extension, size_bytes,
                    sha256_hash, recovery_grade, source_offset, source_lba, provenance, metadata_json, recovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.object_id,
                    record.case_id,
                    record.exhibit_id,
                    record.name,
                    record.extension,
                    record.size_bytes,
                    record.sha256_hash,
                    record.recovery_grade.value,
                    record.source_offset,
                    record.source_lba,
                    record.provenance,
                    record.metadata_json,
                    record.recovered_at,
                ),
            )
        return record

    def list_recovered_objects(self, case_id: str) -> List[RecoveredObjectRecord]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM recovered_objects WHERE case_id = ? ORDER BY recovered_at ASC", (case_id,))
        objs = []
        for r in cur.fetchall():
            objs.append(
                RecoveredObjectRecord(
                    object_id=r["object_id"],
                    case_id=r["case_id"],
                    exhibit_id=r["exhibit_id"],
                    name=r["name"],
                    extension=r["extension"],
                    size_bytes=r["size_bytes"],
                    sha256_hash=r["sha256_hash"],
                    recovery_grade=RecoveryGrade(r["recovery_grade"]),
                    source_offset=r["source_offset"],
                    source_lba=r["source_lba"],
                    provenance=r["provenance"],
                    metadata_json=r["metadata_json"],
                    recovered_at=r["recovered_at"],
                )
            )
        return objs

    # -------------------------------------------------------------------------
    # Jobs, Images & Certificates
    # -------------------------------------------------------------------------

    def record_job(
        self,
        case_id: str,
        job_type: str,
        status: str = "COMPLETED",
        device_serial: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        summary: Optional[str] = None,
    ) -> JobRecord:
        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        record = JobRecord(
            job_id=job_id,
            case_id=case_id,
            job_type=job_type,
            device_serial=device_serial,
            status=status,
            completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            parameters=parameters or {},
            summary=summary,
        )
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO jobs (job_id, case_id, job_type, device_serial, status, started_at, completed_at, parameters, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.job_id,
                    record.case_id,
                    record.job_type,
                    record.device_serial,
                    record.status,
                    record.started_at,
                    record.completed_at,
                    json.dumps(record.parameters),
                    record.summary,
                ),
            )
        return record

    def record_image(
        self,
        case_id: str,
        format_name: str,
        file_path: str,
        size_bytes: int,
        sha256_hash: str,
        source_serial: str,
        exhibit_id: Optional[str] = None,
        segment_count: int = 1,
    ) -> ImageRecord:
        img_id = f"IMG-{uuid.uuid4().hex[:8].upper()}"
        record = ImageRecord(
            image_id=img_id,
            case_id=case_id,
            exhibit_id=exhibit_id,
            format=format_name,
            file_path=file_path,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            source_serial=source_serial,
            segment_count=segment_count,
        )
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO images (image_id, case_id, exhibit_id, format, file_path, size_bytes, sha256_hash, source_serial, segment_count, acquired_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.image_id,
                    record.case_id,
                    record.exhibit_id,
                    record.format,
                    record.file_path,
                    record.size_bytes,
                    record.sha256_hash,
                    record.source_serial,
                    record.segment_count,
                    record.acquired_at,
                ),
            )
        return record

    def record_certificate(
        self,
        certificate_id: str,
        certificate_type: str,
        device_serial: str,
        result: str,
        method: str,
        sha256_hash: str,
        signature: str,
        case_id: Optional[str] = None,
        payload_json: str = "{}",
    ) -> CertificateRecord:
        record = CertificateRecord(
            certificate_id=certificate_id,
            case_id=case_id,
            certificate_type=certificate_type,
            device_serial=device_serial,
            result=result,
            method=method,
            sha256_hash=sha256_hash,
            signature=signature,
            payload_json=payload_json,
        )
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO certificates (certificate_id, case_id, certificate_type, device_serial, result, method, sha256_hash, signature, issued_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.certificate_id,
                    record.case_id,
                    record.certificate_type,
                    record.device_serial,
                    record.result,
                    record.method,
                    record.sha256_hash,
                    record.signature,
                    record.issued_at,
                    record.payload_json,
                ),
            )
        return record
