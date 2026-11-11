from typing import Optional, Dict, Any
from sanctum.acquisition.models import ImageFormat
from sanctum.acquisition.formats.base import BaseImageWriter
from sanctum.acquisition.formats.raw import RawImageWriter
from sanctum.acquisition.formats.e01 import E01ImageWriter
from sanctum.acquisition.formats.aff4 import AFF4ImageWriter


def get_image_writer(
    image_format: ImageFormat,
    output_path: str,
    segment_size_bytes: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> BaseImageWriter:
    """Factory creating appropriate forensic image writer based on format."""
    if image_format == ImageFormat.RAW:
        return RawImageWriter(output_path, segment_size_bytes=segment_size_bytes)
    elif image_format == ImageFormat.E01:
        return E01ImageWriter(output_path, segment_size_bytes=segment_size_bytes, metadata=metadata)
    elif image_format == ImageFormat.AFF4:
        return AFF4ImageWriter(output_path, segment_size_bytes=segment_size_bytes, metadata=metadata)
    else:
        raise ValueError(f"Unsupported image format: {image_format}")
