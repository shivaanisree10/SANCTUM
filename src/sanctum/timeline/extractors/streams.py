import configparser
import io
from typing import Dict, Any, Optional
from ..models import AlternateDataStream


def parse_zone_identifier(content: str) -> Dict[str, str]:
    """
    Parses Windows Zone.Identifier INI payload.
    Example:
    [ZoneTransfer]
    ZoneId=3
    HostUrl=https://example.com/malware.exe
    ReferrerUrl=https://google.com
    """
    res: Dict[str, str] = {}
    config = configparser.ConfigParser()
    try:
        config.read_string(content)
        if "ZoneTransfer" in config:
            for k, v in config["ZoneTransfer"].items():
                res[k] = v
    except Exception:
        # Fallback to line-by-line parsing if malformed INI
        for line in content.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                res[k.strip().lower()] = v.strip()
    return res


def extract_alternate_data_stream(stream_name: str, stream_bytes: bytes) -> AlternateDataStream:
    """
    Extracts information from an NTFS Alternate Data Stream,
    parsing Zone.Identifier if applicable.
    """
    zone_info: Optional[Dict[str, str]] = None
    if "zone.identifier" in stream_name.lower():
        try:
            text = stream_bytes.decode("utf-8", errors="replace")
            zone_info = parse_zone_identifier(text)
        except Exception:
            pass

    return AlternateDataStream(
        stream_name=stream_name,
        size_bytes=len(stream_bytes),
        zone_identifier=zone_info
    )
