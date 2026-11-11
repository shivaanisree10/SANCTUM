from sanctum.fs.models import (
    FileEntry,
    FileEntryType,
    FileMetadata,
    Extent,
)
from sanctum.fs.base import (
    BaseFileSystemParser,
    FileSystemError,
    ParserTimeoutError,
    ParserRecursionLimitError,
    ParserCycleDetectedError,
)
from sanctum.fs.registry import FileSystemRegistry
from sanctum.fs.tsk import TSKFileSystemParser
from sanctum.fs.fat import FATParser
from sanctum.fs.ntfs import NTFSParser
from sanctum.fs.exfat import ExFATParser
from sanctum.fs.ext import ExtParser
from sanctum.fs.apfs import APFSParser

# Default pre-configured registry
default_fs_registry = FileSystemRegistry()
default_fs_registry.register(TSKFileSystemParser)
default_fs_registry.register(NTFSParser)
default_fs_registry.register(FATParser)
default_fs_registry.register(ExFATParser)
default_fs_registry.register(ExtParser)
default_fs_registry.register(APFSParser)

__all__ = [
    "FileEntry",
    "FileEntryType",
    "FileMetadata",
    "Extent",
    "BaseFileSystemParser",
    "FileSystemError",
    "ParserTimeoutError",
    "ParserRecursionLimitError",
    "ParserCycleDetectedError",
    "FileSystemRegistry",
    "default_fs_registry",
    "TSKFileSystemParser",
    "FATParser",
    "NTFSParser",
    "ExFATParser",
    "ExtParser",
    "APFSParser",
]
