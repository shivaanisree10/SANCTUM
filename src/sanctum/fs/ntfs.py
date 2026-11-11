import struct
import time
import logging
from typing import List, Optional, Dict, Any, Tuple
from sanctum.dal import BaseDevice
from sanctum.fs.base import BaseFileSystemParser
from sanctum.fs.models import FileEntry, FileEntryType, FileMetadata, Extent

logger = logging.getLogger("sanctum.fs.ntfs")

NTFS_BOOT_SIG = b"\x55\xaa"
MFT_RECORD_MAGIC = b"FILE"


class NTFSParser(BaseFileSystemParser):
    """
    Forensic NTFS Parser with specialized forensic modules for:
    - MFT record parsing (allocated & deleted files)
    - $UsnJrnl ($J) change journal stream decoding
    - $LogFile transaction journal decoding
    """

    @classmethod
    def probe(cls, device: BaseDevice) -> float:
        try:
            sector = device.read_sector(0)
            if len(sector) < 512 or sector[510:512] != NTFS_BOOT_SIG:
                return 0.0

            if sector[3:11] == b"NTFS    ":
                return 0.98

            return 0.0
        except Exception:
            return 0.0

    def __init__(self, device: BaseDevice, **kwargs):
        super().__init__(device, **kwargs)
        self._load_vbr()

    def _load_vbr(self) -> None:
        sector = self.device.read_sector(0)
        self.bytes_per_sec = struct.unpack("<H", sector[11:13])[0] or 512
        if self.bytes_per_sec not in (512, 1024, 2048, 4096):
            self.bytes_per_sec = 512
        self.sec_per_cluster = sector[13] or 8
        if self.sec_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
            self.sec_per_cluster = 8
        self.total_sectors = min(struct.unpack("<Q", sector[40:48])[0], self.device.info.lba_count)
        self.mft_cluster = min(struct.unpack("<Q", sector[48:56])[0], self.device.info.lba_count)
        self.mft_record_size_encoded = struct.unpack("<b", sector[64:65])[0]

        # Calculate MFT record size with defensive bounds
        if self.mft_record_size_encoded < 0 and (-self.mft_record_size_encoded) <= 16:
            self.mft_record_size = 1 << (-self.mft_record_size_encoded)  # usually 1024 bytes
        elif self.mft_record_size_encoded > 0:
            self.mft_record_size = min(self.mft_record_size_encoded * self.sec_per_cluster * self.bytes_per_sec, 4096)
        else:
            self.mft_record_size = 1024

        if self.mft_record_size not in (1024, 2048, 4096):
            self.mft_record_size = 1024

        self.cluster_size = self.bytes_per_sec * self.sec_per_cluster
        self.mft_start_lba = min(self.mft_cluster * self.sec_per_cluster, self.device.info.lba_count)

    def _read_mft_record(self, record_index: int) -> Optional[bytes]:
        """Reads a 1024-byte MFT record by record index."""
        record_lba = self.mft_start_lba + ((record_index * self.mft_record_size) // self.bytes_per_sec)
        if record_lba < 0 or record_lba >= self.device.info.lba_count:
            return None
        sectors_needed = min(max(1, self.mft_record_size // self.bytes_per_sec), 8)
        buf = bytearray()
        for i in range(sectors_needed):
            try:
                buf.extend(self.device.read_sector(record_lba + i))
            except Exception:
                buf.extend(b"\x00" * self.bytes_per_sec)
        data = bytes(buf[: self.mft_record_size])
        if data[:4] == MFT_RECORD_MAGIC:
            return data
        return None

    def _parse_mft_record(self, record_bytes: bytes, index: int) -> Optional[FileEntry]:
        """Parses MFT record header and attributes ($STANDARD_INFORMATION, $FILE_NAME, $DATA)."""
        if len(record_bytes) < 48 or record_bytes[:4] != MFT_RECORD_MAGIC:
            return None

        flags = struct.unpack("<H", record_bytes[22:24])[0]
        is_alloc = bool(flags & 0x01)
        is_dir = bool(flags & 0x02)
        is_deleted = not is_alloc

        attr_offset = struct.unpack("<H", record_bytes[20:22])[0]
        filename = f"MFT_Record_{index}"
        filesize = 0
        resident_data = None
        data_extents: List[Extent] = []

        curr_off = attr_offset
        while curr_off + 8 <= len(record_bytes):
            attr_type, attr_len = struct.unpack("<II", record_bytes[curr_off : curr_off + 8])
            if attr_type == 0xFFFFFFFF or attr_len == 0:
                break

            attr_body = record_bytes[curr_off : curr_off + attr_len]

            # $FILE_NAME Attribute (0x30)
            if attr_type == 0x30:
                non_res = attr_body[8]
                if non_res == 0:  # Resident
                    content_off = struct.unpack("<H", attr_body[20:22])[0]
                    name_len = attr_body[content_off + 64]
                    name_bytes = attr_body[content_off + 66 : content_off + 66 + (name_len * 2)]
                    try:
                        decoded_name = name_bytes.decode("utf-16le")
                        if decoded_name and not filename.startswith("$"):
                            filename = decoded_name
                    except Exception:
                        pass

            # $DATA Attribute (0x80)
            elif attr_type == 0x80:
                non_res = attr_body[8]
                if non_res == 0:  # Resident
                    content_off = struct.unpack("<H", attr_body[20:22])[0]
                    content_len = struct.unpack("<I", attr_body[16:20])[0]
                    filesize = content_len
                    resident_data = attr_body[content_off : content_off + content_len]
                else:  # Non-resident
                    real_size = struct.unpack("<Q", attr_body[48:56])[0]
                    filesize = real_size

            curr_off += attr_len

        entry = FileEntry(
            id=str(index),
            path=f"/{filename}",
            name=filename,
            entry_type=FileEntryType.DIRECTORY if is_dir else FileEntryType.FILE,
            is_deleted=is_deleted,
            size_bytes=filesize,
            internal_ref={"resident_data": resident_data, "mft_index": index},
        )
        return entry

    def list_allocated(self) -> List[FileEntry]:
        return self._scan_mft(include_deleted=False)

    def list_deleted(self) -> List[FileEntry]:
        return self._scan_mft(include_deleted=True)

    def _scan_mft(self, include_deleted: bool, max_records: int = 1024) -> List[FileEntry]:
        entries: List[FileEntry] = []
        limit = min(max_records, self.device.info.lba_count, 256)
        for i in range(limit):
            rec = self._read_mft_record(i)
            if rec:
                entry = self._parse_mft_record(rec, i)
                if entry:
                    if (not include_deleted and not entry.is_deleted) or (
                        include_deleted and entry.is_deleted
                    ):
                        entries.append(entry)
        return entries

    def read_file_data(
        self, file_info: FileEntry, offset: int = 0, size: Optional[int] = None
    ) -> bytes:
        if not file_info.internal_ref:
            return b""
        res = file_info.internal_ref.get("resident_data")
        if res:
            target_size = size or len(res)
            target_size = self.clamp_allocation_size(target_size)
            return res[offset : offset + target_size]
        return b""

    def get_metadata(self, file_info: FileEntry) -> FileMetadata:
        return FileMetadata(size_bytes=file_info.size_bytes)

    def get_unallocated_extents(self) -> List[Extent]:
        # NTFS unallocated extents via $Bitmap or volume capacity
        return []

    # =========================================================================
    # FORENSIC ARTIFACT ANALYSIS: $UsnJrnl and $LogFile
    # =========================================================================

    @staticmethod
    def parse_usn_records(data: bytes) -> List[Dict[str, Any]]:
        """
        Parses NTFS Update Sequence Number (USN) Journal v2/v3 records.
        """
        records: List[Dict[str, Any]] = []
        offset = 0

        while offset + 60 <= len(data):
            rec_len = struct.unpack("<I", data[offset : offset + 4])[0]
            if rec_len == 0 or offset + rec_len > len(data):
                break

            major_ver, minor_ver = struct.unpack("<HH", data[offset + 4 : offset + 8])
            if major_ver in (2, 3):
                frn, parent_frn = struct.unpack("<QQ", data[offset + 8 : offset + 24])
                usn = struct.unpack("<Q", data[offset + 24 : offset + 32])[0]
                timestamp_raw = struct.unpack("<Q", data[offset + 32 : offset + 40])[0]
                reason = struct.unpack("<I", data[offset + 40 : offset + 44])[0]
                file_attr = struct.unpack("<I", data[offset + 52 : offset + 56])[0]
                name_len = struct.unpack("<H", data[offset + 56 : offset + 58])[0]
                name_offset = struct.unpack("<H", data[offset + 58 : offset + 60])[0]

                name = ""
                if offset + name_offset + name_len <= len(data):
                    try:
                        name = data[
                            offset + name_offset : offset + name_offset + name_len
                        ].decode("utf-16le")
                    except Exception:
                        name = "UNKNOWN"

                records.append({
                    "version": f"{major_ver}.{minor_ver}",
                    "usn": usn,
                    "file_ref": frn,
                    "parent_ref": parent_frn,
                    "timestamp": timestamp_raw,
                    "reason_flags": reason,
                    "file_attributes": file_attr,
                    "filename": name,
                })

            offset += rec_len

        return records

    @staticmethod
    def parse_logfile_pages(data: bytes) -> List[Dict[str, Any]]:
        """
        Parses NTFS $LogFile pages (RSTR restart areas and RCRD record blocks).
        """
        pages: List[Dict[str, Any]] = []
        page_size = 512
        offset = 0

        while offset + page_size <= len(data):
            page_data = data[offset : offset + page_size]
            magic = page_data[:4]

            if magic in (b"RSTR", b"RCRD"):
                lsn = struct.unpack("<Q", page_data[8:16])[0] if len(page_data) >= 16 else 0
                pages.append({
                    "page_type": magic.decode("ascii"),
                    "page_offset": offset,
                    "lsn": lsn,
                })

            offset += page_size

        return pages
