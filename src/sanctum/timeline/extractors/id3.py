import struct
from typing import Dict, Any


def extract_id3_metadata(data: bytes) -> Dict[str, Any]:
    """
    Extracts ID3v1 and ID3v2 tags from MP3 audio data.
    ID3v1 is located in the last 128 bytes (TAG...).
    ID3v2 starts at byte 0 with ID3 tag.
    """
    metadata: Dict[str, Any] = {}

    # Check ID3v2 at the beginning
    if len(data) >= 10 and data.startswith(b"ID3"):
        major_ver = data[3]
        rev_ver = data[4]
        flags = data[5]
        # Syncsafe integer for header size
        tag_size = ((data[6] & 0x7F) << 21) | ((data[7] & 0x7F) << 14) | ((data[8] & 0x7F) << 7) | (data[9] & 0x7F)
        metadata["id3_version"] = f"2.{major_ver}.{rev_ver}"
        
        offset = 10
        limit = min(len(data), 10 + tag_size)
        
        while offset + 10 <= limit:
            frame_id = data[offset:offset+4].decode("latin-1", errors="ignore")
            if not frame_id or frame_id[0] == '\x00':
                break
                
            if major_ver == 4:
                # v2.4 uses syncsafe integer for frame size
                frame_size = ((data[offset+4] & 0x7F) << 21) | ((data[offset+5] & 0x7F) << 14) | ((data[offset+6] & 0x7F) << 7) | (data[offset+7] & 0x7F)
            else:
                frame_size = struct.unpack(">I", data[offset+4:offset+8])[0]
                
            offset += 10
            if offset + frame_size > limit or frame_size <= 0:
                break
                
            frame_data = data[offset:offset+frame_size]
            offset += frame_size
            
            # Frame mapping
            # TIT2: Title, TPE1: Artist, TALB: Album, TYER: Year (v2.3), TDRC: Recording time (v2.4), COMM: Comment
            val = ""
            if frame_size > 1:
                encoding = frame_data[0]
                raw_payload = frame_data[1:]
                try:
                    if encoding == 0:
                        val = raw_payload.decode("latin-1", errors="replace").strip("\x00")
                    elif encoding == 1:
                        val = raw_payload.decode("utf-16", errors="replace").strip("\x00")
                    elif encoding == 2:
                        val = raw_payload.decode("utf-16-be", errors="replace").strip("\x00")
                    elif encoding == 3:
                        val = raw_payload.decode("utf-8", errors="replace").strip("\x00")
                    else:
                        val = raw_payload.decode("latin-1", errors="replace").strip("\x00")
                except Exception:
                    pass
            
            if val:
                if frame_id == "TIT2":
                    metadata["title"] = val
                elif frame_id == "TPE1":
                    metadata["artist"] = val
                elif frame_id == "TALB":
                    metadata["album"] = val
                elif frame_id in ("TYER", "TDRC"):
                    metadata["year"] = val
                elif frame_id == "COMM":
                    metadata["comment"] = val

    # Check ID3v1 at the end (last 128 bytes)
    if len(data) >= 128 and data[-128:-125] == b"TAG":
        tag = data[-128:]
        title = tag[3:33].decode("latin-1", errors="replace").strip("\x00 \t\r\n")
        artist = tag[33:63].decode("latin-1", errors="replace").strip("\x00 \t\r\n")
        album = tag[63:93].decode("latin-1", errors="replace").strip("\x00 \t\r\n")
        year = tag[93:97].decode("latin-1", errors="replace").strip("\x00 \t\r\n")
        
        if "title" not in metadata and title:
            metadata["title"] = title
        if "artist" not in metadata and artist:
            metadata["artist"] = artist
        if "album" not in metadata and album:
            metadata["album"] = album
        if "year" not in metadata and year:
            metadata["year"] = year

    return metadata
