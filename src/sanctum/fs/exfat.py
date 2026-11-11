import struct
import logging
from typing import List, Optional, Tuple, Dict, Any
from sanctum.dal import BaseDevice
from sanctum.fs.base import BaseFileSystemParser
from sanctum.fs.models import FileEntry, FileEntryType, FileMetadata, Extent

logger = logging.getLogger("sanctum.fs.exfat")

EXFAT_BOOT_SIG = b"\x55\xaa"


class ExFATParser(BaseFileSystemParser):
    """
    Forensic Parser for exFAT filesystems.
    Features:
    - VBR parameter decoding
    - exFAT directory entry parsing (File 0x85, Stream Ext 0xC0, File Name 0xC1)
    - Deleted directory entry detection (0x05 / 0x40 / 0x41)
    - Unallocated cluster extent extraction via Allocation Bitmap (0x81)
    """

    @classmethod
    def probe(cls, device: BaseDevice) -> float:
        try:
            sector = device.read_sector(0)
            if len(sector) < 512 or sector[510:512] != EXFAT_BOOT_SIG:
                return 0.0

            if sector[3:11] == b"EXFAT   ":
                return 0.98

            return 0.0
        except Exception:
            return 0.0

    def __init__(self, device: BaseDevice, **kwargs):
        super().__init__(device, **kwargs)
        self._load_vbr()

    def _load_vbr(self) -> None:
        sector = self.device.read_sector(0)
        self.bytes_per_sec_shift = sector[108] or 9
        if self.bytes_per_sec_shift not in (9, 10, 11, 12):
            self.bytes_per_sec_shift = 9
        self.sec_per_cluster_shift = sector[109] or 3
        if self.sec_per_cluster_shift > 12:
            self.sec_per_cluster_shift = 3
        self.bytes_per_sec = 1 << self.bytes_per_sec_shift
        self.sec_per_cluster = 1 << self.sec_per_cluster_shift
        self.cluster_size = self.bytes_per_sec * self.sec_per_cluster

        self.fat_offset_lba = struct.unpack("<I", sector[80:84])[0]
        self.cluster_heap_offset_lba = struct.unpack("<I", sector[88:92])[0]
        self.cluster_count = min(struct.unpack("<I", sector[92:96])[0], self.device.info.lba_count)
        self.root_cluster = struct.unpack("<I", sector[96:100])[0]

        self.bitmap_start_cluster = 0
        self.bitmap_size = 0

    def cluster_to_lba(self, cluster: int) -> int:
        return self.cluster_heap_offset_lba + ((cluster - 2) * self.sec_per_cluster)

    def _read_cluster(self, cluster: int) -> bytes:
        if cluster < 2 or cluster >= self.cluster_count + 2:
            return b""
        start_lba = self.cluster_to_lba(cluster)
        if start_lba < 0 or start_lba >= self.device.info.lba_count:
            return b""
        buf = bytearray()
        for s in range(self.sec_per_cluster):
            try:
                buf.extend(self.device.read_sector(start_lba + s))
            except Exception:
                buf.extend(b"\x00" * self.bytes_per_sec)
        return bytes(buf)

    def _parse_directory_set(self, data: bytes, include_deleted: bool) -> List[FileEntry]:
        """
        Parses exFAT directory entry sets (0x85 File, 0xC0 Stream Extension, 0xC1 File Name).
        """
        entries: List[FileEntry] = []
        offset = 0

        while offset + 32 <= len(data):
            entry_type = data[offset]
            if entry_type == 0x00:
                break  # End of directory markers

            # In exFAT:
            # Type 0x85: File Directory Entry (in-use)
            # Type 0x05: Deleted File Directory Entry
            is_file_entry = (entry_type & 0x7F) == 0x05
            is_in_use = bool(entry_type & 0x80)
            is_deleted = not is_in_use

            if is_file_entry:
                if (not include_deleted and is_deleted) or (include_deleted and not is_deleted):
                    # Skip non-matching status
                    offset += 32
                    continue

                secondary_count = data[offset + 1]
                attr = struct.unpack("<H", data[offset + 4 : offset + 6])[0]
                is_dir = bool(attr & 0x10)

                # Expect next entry to be 0xC0 (Stream Extension)
                stream_off = offset + 32
                file_size = 0
                first_cluster = 0
                filename_parts = []

                if stream_off + 32 <= len(data):
                    stream_type = data[stream_off]
                    if (stream_type & 0x7F) == 0x40:  # 0xC0 or 0x40
                        name_len = data[stream_off + 3]
                        file_size = struct.unpack("<Q", data[stream_off + 24 : stream_off + 32])[0]
                        first_cluster = struct.unpack("<I", data[stream_off + 20 : stream_off + 24])[0]

                        # Read File Name entries (0xC1)
                        fn_off = stream_off + 32
                        for _ in range(secondary_count - 1):
                            if fn_off + 32 <= len(data):
                                fn_type = data[fn_off]
                                if (fn_type & 0x7F) == 0x41:  # 0xC1 or 0x41
                                    name_chunk = data[fn_off + 2 : fn_off + 32]
                                    try:
                                        filename_parts.append(name_chunk.decode("utf-16le"))
                                    except Exception:
                                        pass
                                fn_off += 32

                full_name = "".join(filename_parts).rstrip("\x00") or f"exfat_entry_{offset}"

                entry = FileEntry(
                    id=f"exfat_c{first_cluster}_{full_name}",
                    path=f"/{full_name}",
                    name=full_name,
                    entry_type=FileEntryType.DIRECTORY if is_dir else FileEntryType.FILE,
                    is_deleted=is_deleted,
                    size_bytes=file_size,
                    internal_ref={"first_cluster": first_cluster},
                )
                entries.append(entry)
                offset += 32 * (1 + secondary_count)
            elif entry_type == 0x81:
                # Allocation Bitmap entry
                first_cluster = struct.unpack("<I", data[offset + 20 : offset + 24])[0]
                size = struct.unpack("<Q", data[offset + 24 : offset + 32])[0]
                self.bitmap_start_cluster = first_cluster
                self.bitmap_size = size
                offset += 32
            else:
                offset += 32

        return entries

    def list_allocated(self) -> List[FileEntry]:
        root_data = self._read_cluster(self.root_cluster)
        return self._parse_directory_set(root_data, include_deleted=False)

    def list_deleted(self) -> List[FileEntry]:
        root_data = self._read_cluster(self.root_cluster)
        return self._parse_directory_set(root_data, include_deleted=True)

    def read_file_data(
        self, file_info: FileEntry, offset: int = 0, size: Optional[int] = None
    ) -> bytes:
        if not file_info.internal_ref:
            return b""
        first_cluster = file_info.internal_ref.get("first_cluster", 0)
        if first_cluster < 2:
            return b""

        target_size = size or file_info.size_bytes
        target_size = self.clamp_allocation_size(target_size)

        data = self._read_cluster(first_cluster)
        return data[offset : offset + target_size]

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
        """
        Parses Allocation Bitmap (0x81): 0 = Free Cluster, 1 = Allocated Cluster.
        Extracts contiguous runs of free clusters.
        """
        extents: List[Extent] = []
        if self.bitmap_start_cluster < 2:
            # Fallback scan root directory for bitmap entry
            root_data = self._read_cluster(self.root_cluster)
            self._parse_directory_set(root_data, include_deleted=False)

        if self.bitmap_start_cluster >= 2:
            bitmap_data = self._read_cluster(self.bitmap_start_cluster)
            start_cluster = None
            run_len = 0

            for byte_idx, b in enumerate(bitmap_data):
                for bit_idx in range(8):
                    cluster_idx = (byte_idx * 8) + bit_idx + 2
                    if cluster_idx >= self.cluster_count + 2:
                        break

                    is_allocated = bool(b & (1 << bit_idx))
                    if not is_allocated:  # Free
                        if start_cluster is None:
                            start_cluster = cluster_idx
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
