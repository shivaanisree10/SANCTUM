import io
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from datetime import datetime, timezone


def extract_office_properties(data: bytes) -> Dict[str, Any]:
    """
    Extracts metadata from Office Open XML (DOCX, XLSX, PPTX) packages.
    Reads docProps/core.xml and docProps/app.xml.
    """
    properties: Dict[str, Any] = {}
    if not (data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08")):
        return properties

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as z:
            names = z.namelist()
            
            # 1. docProps/core.xml (Dublin Core / Open Packaging Conventions)
            for name in names:
                if name.lower() in ("docprops/core.xml", "core.xml"):
                    xml_bytes = z.read(name)
                    try:
                        root = ET.fromstring(xml_bytes)
                    except ET.ParseError:
                        # Fallback regex parsing if XML has unbound namespaces
                        import re
                        for m in re.finditer(rb"<(?:\w+:)?(\w+)[^>]*>(.*?)</(?:\w+:)?\1>", xml_bytes, re.DOTALL):
                            tag = m.group(1).decode("latin-1").lower()
                            val = m.group(2).decode("utf-8", errors="replace").strip()
                            if tag == "title":
                                properties["title"] = val
                            elif tag in ("creator", "author"):
                                properties["creator"] = val
                            elif tag in ("lastmodifiedby", "last_modified_by"):
                                properties["last_modified_by"] = val
                            elif tag == "revision":
                                properties["revision"] = val
                            elif tag == "created":
                                properties["created"] = val
                            elif tag == "modified":
                                properties["modified"] = val
                        continue
                    
                    # Common namespaces
                    # dc: http://purl.org/dc/elements/1.1/
                    # dcterms: http://purl.org/dc/terms/
                    # cp: http://schemas.openxmlformats.org/package/2006/metadata/core-properties
                    for elem in root.iter():
                        tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        tag_name_lower = tag_name.lower()
                        text_val = (elem.text or "").strip()
                        if not text_val:
                            continue
                        
                        if tag_name_lower == "title":
                            properties["title"] = text_val
                        elif tag_name_lower in ("creator", "author"):
                            properties["creator"] = text_val
                        elif tag_name_lower in ("lastmodifiedby", "last_modified_by"):
                            properties["last_modified_by"] = text_val
                        elif tag_name_lower == "revision":
                            properties["revision"] = text_val
                        elif tag_name_lower == "created":
                            properties["created"] = text_val
                        elif tag_name_lower == "modified":
                            properties["modified"] = text_val
                        elif tag_name_lower == "description":
                            properties["description"] = text_val
                        elif tag_name_lower == "subject":
                            properties["subject"] = text_val

            # 2. docProps/app.xml (Extended Properties)
            for name in names:
                if name.lower() in ("docprops/app.xml", "app.xml"):
                    xml_bytes = z.read(name)
                    root = ET.fromstring(xml_bytes)
                    for elem in root.iter():
                        tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        tag_name_lower = tag_name.lower()
                        text_val = (elem.text or "").strip()
                        if not text_val:
                            continue
                        
                        if tag_name_lower == "application":
                            properties["application"] = text_val
                        elif tag_name_lower == "appversion":
                            properties["app_version"] = text_val
                        elif tag_name_lower == "company":
                            properties["company"] = text_val
                        elif tag_name_lower == "totaltime":
                            properties["total_editing_time"] = text_val
                        elif tag_name_lower == "pages":
                            properties["pages"] = int(text_val) if text_val.isdigit() else text_val
                        elif tag_name_lower == "words":
                            properties["words"] = int(text_val) if text_val.isdigit() else text_val

    except Exception as e:
        properties["_error"] = str(e)

    return properties
