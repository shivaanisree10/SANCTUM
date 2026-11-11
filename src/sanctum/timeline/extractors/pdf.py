import re
from typing import Dict, Any, Optional


def extract_pdf_metadata(data: bytes) -> Dict[str, Any]:
    """
    Extracts PDF /Info dictionary metadata and timestamps.
    Parses /Title, /Author, /Subject, /Keywords, /Creator, /Producer,
    /CreationDate, /ModDate.
    """
    metadata: Dict[str, Any] = {}
    if not (b"%PDF-" in data[:1024]):
        return metadata

    # Search for /Info << ... >> or /Info N 0 R object
    # Let's extract key-values typically found in /Info or XMP metadata
    keys = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"]
    
    # Simple regex search across the PDF buffer (especially useful for deleted/fragmented or raw PDF streams)
    for key in keys:
        pattern = rf"/{key}\s*(?:\((.*?)\)|<([0-9a-fA-F]+)>)"
        matches = re.findall(pattern.encode("latin-1"), data)
        if matches:
            # Take the last match (often updated metadata at the end of PDF)
            lit_val, hex_val = matches[-1]
            if lit_val:
                try:
                    val_str = lit_val.decode("latin-1", errors="replace").strip()
                    # Clean escaped parentheses
                    val_str = val_str.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
                    metadata[key.lower()] = val_str
                except Exception:
                    pass
            elif hex_val:
                try:
                    raw_bytes = bytes.fromhex(hex_val.decode("ascii"))
                    metadata[key.lower()] = raw_bytes.decode("utf-16be" if raw_bytes.startswith(b"\xfe\xff") else "latin-1", errors="replace")
                except Exception:
                    pass

    return metadata
