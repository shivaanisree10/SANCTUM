import datetime
import re
from typing import Tuple, Optional, Union
from zoneinfo import ZoneInfo
from .models import TimestampType, TimestampRecord

WINDOWS_TICK = 10000000
SEC_TO_UNIX_EPOCH = 11644473600


def filetime_to_utc(filetime: int) -> Tuple[str, str]:
    """
    Converts 64-bit Windows FILETIME (100ns intervals since 1601-01-01 UTC)
    to ISO 8601 UTC string.
    Returns: (normalized_utc_str, timezone_info)
    """
    if filetime <= 0:
        return "1601-01-01T00:00:00Z", "UTC"

    try:
        epoch_seconds = (filetime // WINDOWS_TICK) - SEC_TO_UNIX_EPOCH
        subsecond = (filetime % WINDOWS_TICK)
        dt = datetime.datetime.fromtimestamp(epoch_seconds, tz=datetime.timezone.utc)
        if subsecond == 0:
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "UTC"
        else:
            microsecond = subsecond // 10
            dt = dt.replace(microsecond=microsecond)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "UTC"
    except Exception:
        return "1601-01-01T00:00:00Z", "UTC"


def parse_filetime(filetime: int, ts_type: TimestampType = TimestampType.MODIFIED) -> TimestampRecord:
    utc_str, tz_info = filetime_to_utc(filetime)
    return TimestampRecord(
        ts_type=ts_type,
        normalized_utc=utc_str,
        raw_value=filetime,
        raw_format="FILETIME",
        timezone_info=tz_info,
        is_local_time=False,
    )


def unix_epoch_to_utc(epoch: Union[int, float]) -> str:
    """Converts Unix epoch timestamp to ISO 8601 UTC string."""
    try:
        dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "1970-01-01T00:00:00Z"


def parse_unix_epoch(epoch: Union[int, float], ts_type: TimestampType = TimestampType.MODIFIED) -> TimestampRecord:
    utc_str = unix_epoch_to_utc(epoch)
    return TimestampRecord(
        ts_type=ts_type,
        normalized_utc=utc_str,
        raw_value=epoch,
        raw_format="UNIX_EPOCH",
        timezone_info="UTC",
        is_local_time=False,
    )


def dos_datetime_to_utc(
    dos_date: int, dos_time: int, local_tz: Optional[str] = None
) -> Tuple[str, str, bool]:
    """
    Converts legacy FAT DOS Date and Time to UTC.
    FAT timestamps are stored in local time without timezone information.
    Returns: (normalized_utc, timezone_info, is_local_time)
    """
    year = ((dos_date >> 9) & 0x7F) + 1980
    month = max(1, min(12, (dos_date >> 5) & 0x0F))
    day = max(1, min(31, dos_date & 0x1F))

    hour = min(23, (dos_time >> 11) & 0x1F)
    minute = min(59, (dos_time >> 5) & 0x3F)
    second = min(59, (dos_time & 0x1F) * 2)

    try:
        # Validate date and time bounds explicitly
        if month < 1 or month > 12:
            raise ValueError(f"Invalid month: {month}")
        if day < 1 or day > 31:
            raise ValueError(f"Invalid day: {day}")
        if hour < 0 or hour > 23:
            raise ValueError(f"Invalid hour: {hour}")
        if minute < 0 or minute > 59:
            raise ValueError(f"Invalid minute: {minute}")
        if second < 0 or second > 59:
            raise ValueError(f"Invalid second: {second}")

        if local_tz:
            tz = ZoneInfo(local_tz)
            dt_local = datetime.datetime(year, month, day, hour, minute, second, tzinfo=tz)
            dt_utc = dt_local.astimezone(datetime.timezone.utc)
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"), local_tz, True
        else:
            dt_local = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
            return dt_local.strftime("%Y-%m-%dT%H:%M:%SZ"), "LOCAL_UNKNOWN", True
    except Exception:
        return "1980-01-01T00:00:00Z", "LOCAL_UNKNOWN", True


def parse_dos_datetime(
    dos_date: int,
    dos_time: int,
    ts_type: TimestampType = TimestampType.MODIFIED,
    local_tz: Optional[str] = None,
) -> TimestampRecord:
    utc_str, tz_info, is_local = dos_datetime_to_utc(dos_date, dos_time, local_tz)
    return TimestampRecord(
        ts_type=ts_type,
        normalized_utc=utc_str,
        raw_value=f"date:0x{dos_date:04x},time:0x{dos_time:04x}",
        raw_format="DOS_DATETIME",
        timezone_info=tz_info,
        is_local_time=is_local,
    )


def pdf_date_to_utc(pdf_str: str) -> Tuple[str, Optional[str]]:
    """
    Parses PDF date format: D:YYYYMMDDHHmmSS[+/-]HH'mm'
    Normalizes to UTC and returns (utc_string, original_tz_offset).
    """
    m = re.match(
        r"D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([+\-Z])?(\d{2})?'?(\d{2})?'?",
        pdf_str.strip(),
    )
    if not m:
        return "1970-01-01T00:00:00Z", None

    year = int(m.group(1))
    month = int(m.group(2) or 1)
    day = int(m.group(3) or 1)
    hour = int(m.group(4) or 0)
    minute = int(m.group(5) or 0)
    second = int(m.group(6) or 0)

    sign = m.group(7)
    tz_h = int(m.group(8) or 0)
    tz_m = int(m.group(9) or 0)

    if sign in ("+", "-"):
        delta = datetime.timedelta(hours=tz_h, minutes=tz_m)
        if sign == "-":
            delta = -delta
        tz = datetime.timezone(delta)
        tz_str = f"{sign}{tz_h:02d}:{tz_m:02d}"
    else:
        tz = datetime.timezone.utc
        tz_str = "UTC"

    dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=tz)
    dt_utc = dt.astimezone(datetime.timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"), tz_str


def parse_pdf_date(pdf_str: str, ts_type: TimestampType = TimestampType.PDF_CREATED) -> Optional[TimestampRecord]:
    try:
        utc_str, tz_info = pdf_date_to_utc(pdf_str)
        return TimestampRecord(
            ts_type=ts_type,
            normalized_utc=utc_str,
            raw_value=pdf_str,
            raw_format="PDF_DATE",
            timezone_info=tz_info,
            is_local_time=False,
        )
    except Exception:
        return None


def exif_date_to_utc(
    exif_str: str, tz_offset_str: Optional[str] = None
) -> Tuple[str, str, bool]:
    """
    Parses EXIF date string (YYYY:MM:DD HH:MM:SS) and optional offset (+HH:MM).
    """
    try:
        parts = exif_str.strip().split(" ")
        date_parts = [int(p) for p in parts[0].split(":")]
        time_parts = [int(p) for p in parts[1].split(":")]

        if tz_offset_str and (tz_offset_str.startswith("+") or tz_offset_str.startswith("-")):
            sign = 1 if tz_offset_str[0] == "+" else -1
            tz_h = int(tz_offset_str[1:3])
            tz_m = int(tz_offset_str[4:6]) if len(tz_offset_str) >= 6 else 0
            tz = datetime.timezone(sign * datetime.timedelta(hours=tz_h, minutes=tz_m))
            is_local = False
            tz_name = tz_offset_str
        else:
            tz = datetime.timezone.utc
            is_local = True
            tz_name = "LOCAL_UNKNOWN"

        dt = datetime.datetime(
            date_parts[0], date_parts[1], date_parts[2],
            time_parts[0], time_parts[1], time_parts[2],
            tzinfo=tz,
        )
        dt_utc = dt.astimezone(datetime.timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"), tz_name, is_local
    except Exception:
        return "1970-01-01T00:00:00Z", "LOCAL_UNKNOWN", True


def parse_exif_datetime(
    exif_str: str,
    ts_type: TimestampType = TimestampType.EXIF_TAKEN,
    tz_offset_str: Optional[str] = None,
) -> Optional[TimestampRecord]:
    try:
        utc_str, tz_name, is_local = exif_date_to_utc(exif_str, tz_offset_str)
        return TimestampRecord(
            ts_type=ts_type,
            normalized_utc=utc_str,
            raw_value=exif_str,
            raw_format="EXIF_STRING",
            timezone_info=tz_name,
            is_local_time=is_local,
        )
    except Exception:
        return None


def normalize_to_utc(
    dt: datetime.datetime,
    ts_type: TimestampType = TimestampType.MODIFIED,
    raw_format: str = "DATETIME_OBJ",
) -> TimestampRecord:
    if dt.tzinfo is None:
        dt_utc = dt.replace(tzinfo=datetime.timezone.utc)
        is_local = True
        tz_name = "LOCAL_ASSUMED_UTC"
    else:
        dt_utc = dt.astimezone(datetime.timezone.utc)
        is_local = False
        tz_name = str(dt.tzinfo)

    return TimestampRecord(
        ts_type=ts_type,
        normalized_utc=dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        raw_value=dt.isoformat(),
        raw_format=raw_format,
        timezone_info=tz_name,
        is_local_time=is_local,
    )


def convert_timezone(
    dt_str: str, timezone_name: str
) -> Tuple[str, str]:
    """
    Converts UTC datetime string to target timezone, correctly accounting for DST boundaries.
    """
    dt_utc = datetime.datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    tz = ZoneInfo(timezone_name)
    dt_target = dt_utc.astimezone(tz)
    return dt_target.isoformat(), tz.tzname(dt_target) or timezone_name
