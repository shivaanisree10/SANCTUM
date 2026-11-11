import logging
from typing import List, Optional
from sanctum.dal import BaseDevice
from sanctum.fs.base import BaseFileSystemParser
from sanctum.fs.models import FileEntry, FileEntryType, FileMetadata, Extent

logger = logging.getLogger("sanctum.fs.tsk")

try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    pytsk3 = None
    PYTSK3_AVAILABLE = False


class PyTSKDeviceImgInfo:
    """Wrapper exposing BaseDevice to pytsk3.Img_Info if pytsk3 is installed."""
    if PYTSK3_AVAILABLE:
        class _ImgInfo(pytsk3.Img_Info):
            def __init__(self, device: BaseDevice):
                self._device = device
                super().__init__()

            def read(self, offset: int, size: int) -> bytes:
                sector_size = self._device.info.sector_size
                start_lba = offset // sector_size
                end_lba = (offset + size + sector_size - 1) // sector_size
                
                buf = bytearray()
                for lba in range(start_lba, end_lba):
                    try:
                        buf.extend(self._device.read_sector(lba))
                    except Exception:
                        buf.extend(b"\x00" * sector_size)
                
                start_in_buf = offset % sector_size
                return bytes(buf[start_in_buf : start_in_buf + size])

            def get_size(self) -> int:
                return self._device.info.capacity_bytes
    else:
        _ImgInfo = None


class TSKFileSystemParser(BaseFileSystemParser):
    """
    Sleuth Kit filesystem parser adapter using pytsk3.
    Supports NTFS, FAT, exFAT, ext, and HFS+ when pytsk3 native library is available.
    """

    @classmethod
    def probe(cls, device: BaseDevice) -> float:
        if not PYTSK3_AVAILABLE:
            return 0.0

        try:
            img = PyTSKDeviceImgInfo._ImgInfo(device)
            fs = pytsk3.FS_Info(img)
            # Successfully opened through TSK
            fs_type_name = str(fs.info.ftype)
            logger.info(f"TSK successfully probed filesystem type: {fs_type_name}")
            return 0.95
        except Exception:
            return 0.0

    def __init__(self, device: BaseDevice, **kwargs):
        super().__init__(device, **kwargs)
        self._fs = None
        if PYTSK3_AVAILABLE:
            try:
                img = PyTSKDeviceImgInfo._ImgInfo(device)
                self._fs = pytsk3.FS_Info(img)
            except Exception as e:
                logger.warning(f"Could not open pytsk3 FS_Info: {e}")

    def list_allocated(self) -> List[FileEntry]:
        if not self._fs:
            return []
        return self._walk_tsk(include_deleted=False)

    def list_deleted(self) -> List[FileEntry]:
        if not self._fs:
            return []
        return self._walk_tsk(include_deleted=True)

    def _walk_tsk(self, include_deleted: bool) -> List[FileEntry]:
        entries: List[FileEntry] = []
        if not self._fs:
            return entries

        visited_inodes = set()

        def _recurse(directory, current_path: str, depth: int):
            self.check_recursion_depth(depth)
            for f in directory:
                try:
                    name = f.info.name.name.decode("utf-8", errors="replace")
                    if name in [".", ".."]:
                        continue

                    inode = f.info.meta.addr if f.info.meta else None
                    if inode:
                        if inode in visited_inodes:
                            continue
                        visited_inodes.add(inode)

                    is_alloc = (f.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_ALLOC)
                    is_unalloc = (f.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_UNALLOC)

                    if (not include_deleted and not is_alloc) or (include_deleted and not is_unalloc):
                        continue

                    is_dir = (f.info.meta and f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
                    size = f.info.meta.size if f.info.meta else 0
                    full_path = f"{current_path}/{name}".replace("//", "/")

                    entry = FileEntry(
                        id=str(inode or name),
                        path=full_path,
                        name=name,
                        entry_type=FileEntryType.DIRECTORY if is_dir else FileEntryType.FILE,
                        is_deleted=is_unalloc,
                        size_bytes=size,
                    )
                    entries.append(entry)

                    if is_dir and is_alloc:
                        sub_dir = f.as_directory()
                        _recurse(sub_dir, full_path, depth + 1)
                except Exception as e:
                    logger.debug(f"Error reading TSK entry: {e}")

        try:
            root_dir = self._fs.open_dir(path="/")
            _recurse(root_dir, "", 0)
        except Exception as e:
            logger.warning(f"Error traversing TSK root directory: {e}")

        return entries

    def read_file_data(
        self, file_info: FileEntry, offset: int = 0, size: Optional[int] = None
    ) -> bytes:
        if not self._fs:
            return b""
        try:
            f = self._fs.open_meta(inode=int(file_info.id))
            target_size = size or file_info.size_bytes
            target_size = self.clamp_allocation_size(target_size)
            return f.read_random(offset, target_size)
        except Exception as e:
            file_info.errors.append(f"TSK read error: {e}")
            return b""

    def get_metadata(self, file_info: FileEntry) -> FileMetadata:
        if not self._fs:
            return FileMetadata()
        try:
            f = self._fs.open_meta(inode=int(file_info.id))
            meta = f.info.meta
            return FileMetadata(
                size_bytes=meta.size if meta else 0,
                mtime=str(meta.mtime) if meta else None,
                atime=str(meta.atime) if meta else None,
                ctime=str(meta.ctime) if meta else None,
                crtime=str(meta.crtime) if meta else None,
            )
        except Exception:
            return FileMetadata()

    def get_unallocated_extents(self) -> List[Extent]:
        # TSK block walk for unallocated blocks
        extents: List[Extent] = []
        if not self._fs:
            return extents
        # Fallback to empty if not fully implemented in pytsk3 build
        return extents
