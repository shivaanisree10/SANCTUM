import struct
from typing import Dict, Any, Tuple, Optional
from sanctum.timeline.timestamps import exif_date_to_utc


def parse_dms(rational_dms: Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]], ref: str) -> float:
    """Converts (Degrees, Minutes, Seconds) rational pairs to signed decimal degrees."""
    d = rational_dms[0][0] / rational_dms[0][1] if rational_dms[0][1] else 0.0
    m = rational_dms[1][0] / rational_dms[1][1] if rational_dms[1][1] else 0.0
    s = rational_dms[2][0] / rational_dms[2][1] if rational_dms[2][1] else 0.0
    val = d + (m / 60.0) + (s / 3600.0)
    if ref.upper() in ("S", "W"):
        val = -val
    return round(val, 6)


def extract_exif_metadata(data: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Extracts EXIF and GPS metadata from JPEG or TIFF images.
    Returns: (exif_dict, gps_dict)
    """
    exif: Dict[str, Any] = {}
    gps: Dict[str, Any] = {}

    if not data:
        return exif, gps

    # Locate Exif APP1 marker in JPEG
    app1_idx = data.find(b"\xff\xe1")
    if app1_idx == -1:
        # Check if direct TIFF header
        if not (data.startswith(b"II*\x00") or data.startswith(b"MM\x00*")):
            return exif, gps
        tiff_data = data
    else:
        # Offset + 2 bytes length + "Exif\x00\x00" (6 bytes)
        exif_marker_pos = data.find(b"Exif\x00\x00", app1_idx)
        if exif_marker_pos == -1 or exif_marker_pos > app1_idx + 10:
            return exif, gps
        tiff_data = data[exif_marker_pos + 6 :]

    if len(tiff_data) < 8:
        return exif, gps

    is_le = tiff_data.startswith(b"II*\x00")
    is_be = tiff_data.startswith(b"MM\x00*")
    if not is_le and not is_be:
        return exif, gps

    fmt = "<" if is_le else ">"

    try:
        ifd0_offset = struct.unpack(f"{fmt}I", tiff_data[4:8])[0]
        if ifd0_offset >= len(tiff_data):
            return exif, gps

        num_entries = struct.unpack(f"{fmt}H", tiff_data[ifd0_offset : ifd0_offset + 2])[0]
        curr = ifd0_offset + 2
        gps_ifd_offset = None
        sub_ifd_offset = None

        TAG_MAP = {
            0x010F: "Make",
            0x0110: "Model",
            0x0131: "Software",
            0x0132: "DateTime",
            0x9003: "DateTimeOriginal",
            0x9004: "DateTimeDigitized",
        }

        for _ in range(min(num_entries, 128)):
            if curr + 12 > len(tiff_data):
                break
            tag, val_type, count, val_or_off = struct.unpack(f"{fmt}HHI4s", tiff_data[curr : curr + 12])
            curr += 12

            # Tag 0x8825: GPS IFD pointer
            if tag == 0x8825:
                gps_ifd_offset = struct.unpack(f"{fmt}I", val_or_off)[0]
            # Tag 0x8769: Exif SubIFD pointer
            elif tag == 0x8769:
                sub_ifd_offset = struct.unpack(f"{fmt}I", val_or_off)[0]
            elif tag in TAG_MAP:
                # String value
                val_offset = struct.unpack(f"{fmt}I", val_or_off)[0] if count > 4 else 0
                if val_offset > 0 and val_offset + count <= len(tiff_data):
                    s_val = tiff_data[val_offset : val_offset + count].decode("ascii", errors="replace").rstrip("\x00")
                else:
                    s_val = val_or_off[:count].decode("ascii", errors="replace").rstrip("\x00")
                exif[TAG_MAP[tag]] = s_val

        # Parse SubIFD for DateTimeOriginal if available
        if sub_ifd_offset and sub_ifd_offset + 2 <= len(tiff_data):
            sub_count = struct.unpack(f"{fmt}H", tiff_data[sub_ifd_offset : sub_ifd_offset + 2])[0]
            s_curr = sub_ifd_offset + 2
            for _ in range(min(sub_count, 64)):
                if s_curr + 12 > len(tiff_data):
                    break
                s_tag, s_type, s_cnt, s_val_off = struct.unpack(f"{fmt}HHI4s", tiff_data[s_curr : s_curr + 12])
                s_curr += 12
                if s_tag in TAG_MAP and TAG_MAP[s_tag] not in exif:
                    v_off = struct.unpack(f"{fmt}I", s_val_off)[0] if s_cnt > 4 else 0
                    if v_off > 0 and v_off + s_cnt <= len(tiff_data):
                        exif[TAG_MAP[s_tag]] = tiff_data[v_off : v_off + s_cnt].decode("ascii", errors="replace").rstrip("\x00")

        # Parse GPS IFD
        if gps_ifd_offset and gps_ifd_offset + 2 <= len(tiff_data):
            gps_entries = struct.unpack(f"{fmt}H", tiff_data[gps_ifd_offset : gps_ifd_offset + 2])[0]
            g_curr = gps_ifd_offset + 2

            gps_lat = None
            gps_lat_ref = "N"
            gps_lon = None
            gps_lon_ref = "E"
            gps_alt = None

            for _ in range(min(gps_entries, 64)):
                if g_curr + 12 > len(tiff_data):
                    break
                g_tag, g_type, g_cnt, g_val_off = struct.unpack(f"{fmt}HHI4s", tiff_data[g_curr : g_curr + 12])
                g_curr += 12

                # 0x0001: GPSLatitudeRef ('N' or 'S')
                if g_tag == 0x0001:
                    gps_lat_ref = g_val_off[:1].decode("ascii", errors="replace")
                # 0x0002: GPSLatitude (3 rationals)
                elif g_tag == 0x0002 and g_cnt == 3:
                    v_off = struct.unpack(f"{fmt}I", g_val_off)[0]
                    if v_off + 24 <= len(tiff_data):
                        r = [struct.unpack(f"{fmt}II", tiff_data[v_off + (i * 8) : v_off + (i * 8) + 8]) for i in range(3)]
                        gps_lat = parse_dms((r[0], r[1], r[2]), gps_lat_ref)
                # 0x0003: GPSLongitudeRef ('E' or 'W')
                elif g_tag == 0x0003:
                    gps_lon_ref = g_val_off[:1].decode("ascii", errors="replace")
                # 0x0004: GPSLongitude (3 rationals)
                elif g_tag == 0x0004 and g_cnt == 3:
                    v_off = struct.unpack(f"{fmt}I", g_val_off)[0]
                    if v_off + 24 <= len(tiff_data):
                        r = [struct.unpack(f"{fmt}II", tiff_data[v_off + (i * 8) : v_off + (i * 8) + 8]) for i in range(3)]
                        gps_lon = parse_dms((r[0], r[1], r[2]), gps_lon_ref)
                # 0x0006: GPSAltitude (1 rational)
                elif g_tag == 0x0006:
                    v_off = struct.unpack(f"{fmt}I", g_val_off)[0]
                    if v_off + 8 <= len(tiff_data):
                        num, den = struct.unpack(f"{fmt}II", tiff_data[v_off : v_off + 8])
                        gps_alt = (num / den) if den else 0.0

            if gps_lat is not None:
                gps["latitude"] = gps_lat
            if gps_lon is not None:
                gps["longitude"] = gps_lon
            if gps_alt is not None:
                gps["altitude_meters"] = round(gps_alt, 2)

    except Exception:
        pass

    return exif, gps


extract_exif_and_gps = extract_exif_metadata
