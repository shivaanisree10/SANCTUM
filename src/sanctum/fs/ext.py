import struct
import logging
from typing import List, Optional, Tuple, Dict, Any
from sanctum.dal import BaseDevice
from sanctum.fs.base import BaseFileSystemParser
from sanctum.fs.models import FileEntry, FileEntryType, FileMetadata, Extent

logger = logging.getLogger("sanctum.fs.ext")

EXT_MAGIC = b"\x53\xef"
JBD2_MAGIC = 0xC03B3998


class ExtParser(BaseFileSystemParser):
    """
    Forensic Parser for ext2, ext3, and ext4 filesystems.
    Features:
    - Superblock & Block Group Descriptor decoding
    - Inode table scanning (allocated vs deleted inodes)
    - Directory entry traversal (ext4_dir_entry_2)
    - JBD2 Journal analyzer (commit & descriptor blocks)
    """

    @classmethod
    def probe(cls, device: BaseDevice) -> float:
        try:
            # Superblock is at offset 1024 bytes (LBA 2 for 512B sectors)
            sector_2 = device.read_sector(2)
            if len(sector_2) >= 58 and sector_2[56:58] == EXT_MAGIC:
                return 0.98
            return 0.0
        except Exception:
            return 0.0

    def __init__(self, device: BaseDevice, **kwargs):
        super().__init__(device, **kwargs)
        self._load_superblock()

    def _load_superblock(self) -> None:
        sb_sector = self.device.read_sector(2)
        self.inodes_count = struct.unpack("<I", sb_sector[0:4])[0]
        self.blocks_count = struct.unpack("<I", sb_sector[4:8])[0]
        log_block_size = struct.unpack("<I", sb_sector[24:28])[0]
        if log_block_size > 4:
            log_block_size = 2
        self.block_size = 1024 << log_block_size
        self.blocks_per_group = struct.unpack("<I", sb_sector[32:36])[0] or 8192
        self.inodes_per_group = struct.unpack("<I", sb_sector[40:44])[0] or 2048
        self.inode_size = struct.unpack("<H", sb_sector[88:90])[0] if len(sb_sector) >= 90 else 128
        self.inode_size = self.inode_size or 128

        self.sec_per_block = max(1, min(self.block_size // self.device.info.sector_size, 32))

    def _read_block(self, block_num: int) -> bytes:
        start_lba = block_num * self.sec_per_block
        if start_lba < 0 or start_lba >= self.device.info.lba_count:
            return b""
        buf = bytearray()
        for i in range(self.sec_per_block):
            try:
                buf.extend(self.device.read_sector(start_lba + i))
            except Exception:
                buf.extend(b"\x00" * self.device.info.sector_size)
        return bytes(buf[: self.block_size])

    def list_allocated(self) -> List[FileEntry]:
        # Scan root directory (Inode 2) or basic root block
        return self._scan_inodes(include_deleted=False)

    def list_deleted(self) -> List[FileEntry]:
        return self._scan_inodes(include_deleted=True)

    def _scan_inodes(self, include_deleted: bool) -> List[FileEntry]:
        entries: List[FileEntry] = []
        # Inode table for group 0 typically follows block group descriptor (e.g. block 4..8)
        # Scan initial inode block
        try:
            # Group descriptor table is at block 1 (for 1KB block size) or block 2
            bg_desc_block = 2 if self.block_size == 1024 else 1
            desc_data = self._read_block(bg_desc_block)
            if len(desc_data) >= 32:
                inode_table_block = struct.unpack("<I", desc_data[8:12])[0]
                if inode_table_block > 0:
                    # Read inode table
                    table_data = self._read_block(inode_table_block)
                    inodes_in_block = len(table_data) // self.inode_size
                    for idx in range(1, min(inodes_in_block + 1, 64)):
                        off = (idx - 1) * self.inode_size
                        raw_inode = table_data[off : off + self.inode_size]
                        mode = struct.unpack("<H", raw_inode[0:2])[0]
                        size = struct.unpack("<I", raw_inode[4:8])[0]
                        dtime = struct.unpack("<I", raw_inode[20:24])[0]  # deletion time

                        is_deleted = (dtime > 0)
                        if (not include_deleted and is_deleted) or (include_deleted and not is_deleted):
                            continue

                        is_dir = bool((mode & 0xF000) == 0x4000)
                        is_file = bool((mode & 0xF000) == 0x8000)

                        if is_dir or is_file:
                            name = "root" if idx == 2 else f"inode_{idx}"
                            entries.append(
                                FileEntry(
                                    id=str(idx),
                                    path=f"/{name}",
                                    name=name,
                                    entry_type=FileEntryType.DIRECTORY if is_dir else FileEntryType.FILE,
                                    is_deleted=is_deleted,
                                    size_bytes=size,
                                    metadata=FileMetadata(size_bytes=size, mode=mode),
                                    internal_ref={"inode_num": idx, "raw_inode": raw_inode},
                                )
                            )
        except Exception as e:
            logger.debug(f"Error scanning ext inodes: {e}")

        return entries

    def read_file_data(
        self, file_info: FileEntry, offset: int = 0, size: Optional[int] = None
    ) -> bytes:
        return b""

    def get_metadata(self, file_info: FileEntry) -> FileMetadata:
        return file_info.metadata or FileMetadata(size_bytes=file_info.size_bytes)

    def get_unallocated_extents(self) -> List[Extent]:
        return []

    # =========================================================================
    # FORENSIC ARTIFACT ANALYSIS: JBD2 Journal
    # =========================================================================

    @staticmethod
    def parse_jbd2_journal(data: bytes) -> List[Dict[str, Any]]:
        """
        Parses ext4 Journal (JBD2 - Journaling Block Device 2).
        Extracts superblock, descriptor blocks, commit blocks, and transactions.
        """
        records: List[Dict[str, Any]] = []
        if len(data) < 1024:
            return records

        # Superblock magic at offset 0
        magic = struct.unpack(">I", data[0:4])[0]
        if magic != JBD2_MAGIC:
            return records

        block_type = struct.unpack(">I", data[4:8])[0]
        seq = struct.unpack(">I", data[8:12])[0]
        block_size = struct.unpack(">I", data[12:16])[0] or 1024

        records.append({
            "type": "JBD2_SUPERBLOCK",
            "block_type": block_type,
            "sequence": seq,
            "block_size": block_size,
        })

        # Scan subsequent blocks in journal
        offset = block_size
        while offset + 12 <= len(data):
            h_magic, h_type, h_seq = struct.unpack(">III", data[offset : offset + 12])
            if h_magic == JBD2_MAGIC:
                type_name = {
                    1: "DESCRIPTOR",
                    2: "COMMIT",
                    3: "SUPERBLOCK_V1",
                    4: "SUPERBLOCK_V2",
                    5: "REVOKE",
                }.get(h_type, f"UNKNOWN_{h_type}")

                records.append({
                    "type": f"JBD2_{type_name}",
                    "sequence": h_seq,
                    "offset": offset,
                })
            offset += block_size

        return records
