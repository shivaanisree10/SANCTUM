import struct
import time
import logging
from typing import List, Optional, Tuple, Set
from sanctum.dal import BaseDevice
from sanctum.fs.base import BaseFileSystemParser
from sanctum.fs.models import FileEntry, FileEntryType, FileMetadata, Extent

logger = logging.getLogger("sanctum.fs.fat")


class FATParser(BaseFileSystemParser):
    """
    Forensic Parser for FAT12, FAT16, and FAT32 filesystems.
    Features:
    - Bounded memory allocations
    - Directory and cluster cycle detection
    - Deleted file detection (0xE5 marker)
    - Unallocated cluster extent extraction
    """

    @classmethod
    def probe(cls, device: BaseDevice) -> float:
        try:
            sector = device.read_sector(0)
            if len(sector) < 512 or sector[510:512] != b"\x55\xaa":
                return 0.0

            bytes_per_sector = struct.unpack("<H", sector[11:13])[0]
            if bytes_per_sector not in (512, 1024, 2048, 4096):
                return 0.0

            sectors_per_cluster = sector[13]
            if sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
                return 0.0

            num_fats = sector[16]
            if num_fats not in (1, 2):
                return 0.0

            # Check FAT strings
            fat32_str = sector[82:90]
            fat16_str = sector[54:62]
            if b"FAT32" in fat32_str:
                return 0.95
            if b"FAT16" in fat16_str or b"FAT12" in fat16_str:
                return 0.95
            if b"MSDOS" in sector[3:11] or b"MSWIN" in sector[3:11]:
                return 0.85

            return 0.70
        except Exception:
            return 0.0

    def __init__(self, device: BaseDevice, **kwargs):
        super().__init__(device, **kwargs)
        self._load_bpb()

    def _load_bpb(self) -> None:
        sector = self.device.read_sector(0)
        self.bytes_per_sec = struct.unpack("<H", sector[11:13])[0] or 512
        if self.bytes_per_sec not in (512, 1024, 2048, 4096):
            self.bytes_per_sec = 512
        self.sec_per_cluster = sector[13] or 1
        if self.sec_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
            self.sec_per_cluster = 1
        self.reserved_sectors = struct.unpack("<H", sector[14:16])[0]
        self.num_fats = sector[16] or 2
        self.root_entries = struct.unpack("<H", sector[17:19])[0]
        total_sectors_16 = struct.unpack("<H", sector[19:21])[0]
        self.total_sectors = min(total_sectors_16 or struct.unpack("<I", sector[32:36])[0], self.device.info.lba_count)
        self.sectors_per_fat = struct.unpack("<H", sector[22:24])[0]

        self.is_fat32 = False
        self.root_cluster = 2
        if self.sectors_per_fat == 0:  # FAT32
            self.is_fat32 = True
            self.sectors_per_fat = struct.unpack("<I", sector[36:40])[0]
            self.root_cluster = struct.unpack("<I", sector[44:48])[0]

        self.cluster_size = self.bytes_per_sec * self.sec_per_cluster
        self.fat_start_lba = self.reserved_sectors
        self.root_dir_sectors = min((self.root_entries * 32 + self.bytes_per_sec - 1) // self.bytes_per_sec, 256)
        self.first_data_sector = self.reserved_sectors + (self.num_fats * self.sectors_per_fat) + self.root_dir_sectors

        data_sectors = max(0, self.total_sectors - self.first_data_sector)
        self.total_clusters = min(data_sectors // self.sec_per_cluster, self.device.info.lba_count)

    def cluster_to_lba(self, cluster: int) -> int:
        return self.first_data_sector + (cluster - 2) * self.sec_per_cluster

    def _get_fat_entry(self, cluster: int) -> int:
        """Reads FAT entry for next cluster pointer."""
        if cluster < 2 or cluster >= self.total_clusters + 2:
            return 0x0FFFFFFF

        if self.is_fat32:
            offset = cluster * 4
            sec_idx = self.fat_start_lba + (offset // self.bytes_per_sec)
            sec_off = offset % self.bytes_per_sec
            try:
                data = self.device.read_sector(sec_idx)
                return struct.unpack("<I", data[sec_off : sec_off + 4])[0] & 0x0FFFFFFF
            except Exception:
                return 0x0FFFFFFF
        else:
            # FAT16
            offset = cluster * 2
            sec_idx = self.fat_start_lba + (offset // self.bytes_per_sec)
            sec_off = offset % self.bytes_per_sec
            try:
                data = self.device.read_sector(sec_idx)
                return struct.unpack("<H", data[sec_off : sec_off + 2])[0]
            except Exception:
                return 0xFFFF

    def _read_cluster(self, cluster: int) -> bytes:
        if cluster < 2 or cluster >= self.total_clusters + 2:
            return b""
        start_lba = self.cluster_to_lba(cluster)
        if start_lba < 0 or start_lba >= self.device.info.lba_count:
            return b""
        buf = bytearray()
        for i in range(self.sec_per_cluster):
            try:
                buf.extend(self.device.read_sector(start_lba + i))
            except Exception:
                buf.extend(b"\x00" * self.bytes_per_sec)
        return bytes(buf)

    def _parse_directory_stream(
        self, stream: bytes, current_path: str, include_deleted: bool, depth: int
    ) -> List[FileEntry]:
        self.check_recursion_depth(depth)
        entries: List[FileEntry] = []
        offset = 0

        while offset + 32 <= len(stream):
            record = stream[offset : offset + 32]
            offset += 32

            first_byte = record[0]
            if first_byte == 0x00:
                break  # End of directory entries

            is_deleted = (first_byte == 0xE5)
            if is_deleted and not include_deleted:
                continue
            if not is_deleted and include_deleted:
                continue

            attr = record[11]
            if attr == 0x0F:
                # Long File Name (LFN) entry; skip for basic short name decoding
                continue

            # Decode 8.3 name
            raw_name = record[:8]
            raw_ext = record[8:11]
            if is_deleted:
                raw_name = b"_" + raw_name[1:]

            try:
                name_str = raw_name.decode("ascii", errors="replace").strip()
                ext_str = raw_ext.decode("ascii", errors="replace").strip()
                filename = f"{name_str}.{ext_str}" if ext_str else name_str
            except Exception:
                filename = "UNKNOWN"

            if filename in (".", ".."):
                continue

            is_dir = bool(attr & 0x10)
            file_size = struct.unpack("<I", record[28:32])[0]
            first_cluster_low = struct.unpack("<H", record[26:28])[0]
            first_cluster_high = struct.unpack("<H", record[20:22])[0] if self.is_fat32 else 0
            first_cluster = (first_cluster_high << 16) | first_cluster_low

            full_path = f"{current_path}/{filename}".replace("//", "/")
            entry = FileEntry(
                id=f"fat_c{first_cluster}_{filename}",
                path=full_path,
                name=filename,
                entry_type=FileEntryType.DIRECTORY if is_dir else FileEntryType.FILE,
                is_deleted=is_deleted,
                size_bytes=file_size,
                internal_ref={"first_cluster": first_cluster},
            )
            entries.append(entry)

            # Recurse into subdirectories if allocated
            if is_dir and not is_deleted and first_cluster >= 2:
                try:
                    sub_stream = self._read_cluster_chain(first_cluster)
                    sub_entries = self._parse_directory_stream(
                        sub_stream, full_path, include_deleted, depth + 1
                    )
                    entries.extend(sub_entries)
                except Exception as e:
                    entry.errors.append(f"Subdir error: {e}")

        return entries

    def _read_cluster_chain(self, start_cluster: int) -> bytes:
        buf = bytearray()
        curr = start_cluster
        visited: Set[int] = set()

        end_marker = 0x0FFFFFF8 if self.is_fat32 else 0xFFF8

        while curr >= 2 and curr < end_marker:
            self.check_cycle(visited, curr)
            buf.extend(self._read_cluster(curr))
            if len(buf) > self.max_alloc_bytes:
                break
            curr = self._get_fat_entry(curr)

        return bytes(buf)

    def list_allocated(self) -> List[FileEntry]:
        root_stream = self._get_root_stream()
        return self._parse_directory_stream(root_stream, "", include_deleted=False, depth=0)

    def list_deleted(self) -> List[FileEntry]:
        root_stream = self._get_root_stream()
        return self._parse_directory_stream(root_stream, "", include_deleted=True, depth=0)

    def _get_root_stream(self) -> bytes:
        if self.is_fat32:
            return self._read_cluster_chain(self.root_cluster)
        else:
            # FAT16/12 root directory is fixed sectors
            buf = bytearray()
            start_lba = self.reserved_sectors + (self.num_fats * self.sectors_per_fat)
            for s in range(self.root_dir_sectors):
                try:
                    buf.extend(self.device.read_sector(start_lba + s))
                except Exception:
                    buf.extend(b"\x00" * self.bytes_per_sec)
            return bytes(buf)

    def read_file_data(
        self, file_info: FileEntry, offset: int = 0, size: Optional[int] = None
    ) -> bytes:
        start_time = time.monotonic()
        if not file_info.internal_ref or "first_cluster" not in file_info.internal_ref:
            return b""

        first_cluster = file_info.internal_ref["first_cluster"]
        if first_cluster < 2:
            return b""

        target_size = size or file_info.size_bytes
        target_size = self.clamp_allocation_size(target_size)

        chain_bytes = self._read_cluster_chain(first_cluster)
        self.check_timeout(start_time)
        return chain_bytes[offset : offset + target_size]

    def get_metadata(self, file_info: FileEntry) -> FileMetadata:
        first_cluster = file_info.internal_ref.get("first_cluster", 0) if file_info.internal_ref else 0
        extents = []
        if first_cluster >= 2:
            lba = self.cluster_to_lba(first_cluster)
            extents.append(
                Extent(
                    start_lba=lba,
                    sector_count=self.sec_per_cluster,
                    offset_bytes=0,
                    size_bytes=self.cluster_size,
                )
            )
        return FileMetadata(
            size_bytes=file_info.size_bytes,
            extents=extents,
            attributes={"first_cluster": first_cluster},
        )

    def get_unallocated_extents(self) -> List[Extent]:
        """Scans FAT table for cluster entry 0 (unallocated clusters) and aggregates extents."""
        extents: List[Extent] = []
        start_cluster = None
        run_len = 0

        for c in range(2, min(self.total_clusters + 2, 65536)):
            entry = self._get_fat_entry(c)
            if entry == 0:  # Free cluster
                if start_cluster is None:
                    start_cluster = c
                    run_len = 1
                else:
                    run_len += 1
            else:
                if start_cluster is not None:
                    lba = self.cluster_to_lba(start_cluster)
                    extents.append(
                        Extent(
                            start_lba=lba,
                            sector_count=run_len * self.sec_per_cluster,
                            offset_bytes=lba * self.bytes_per_sec,
                            size_bytes=run_len * self.cluster_size,
                        )
                    )
                    start_cluster = None
                    run_len = 0

        if start_cluster is not None:
            lba = self.cluster_to_lba(start_cluster)
            extents.append(
                Extent(
                    start_lba=lba,
                    sector_count=run_len * self.sec_per_cluster,
                    offset_bytes=lba * self.bytes_per_sec,
                    size_bytes=run_len * self.cluster_size,
                )
            )

        return extents
