"""Metadata extractor: EXIF image, PDF, DOCX, file hash."""

import hashlib
import json
import os
import zipfile
from typing import Any, Dict, List, Optional


def file_hashes(path: str) -> Dict[str, str]:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest(),
    }


def exif_image(path: str) -> Dict[str, Any]:
    """Ambil metadata EXIF dari gambar (JPG/PNG/TIFF)."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        return {"error": "Pillow belum terinstall. pip install Pillow"}
    out: Dict[str, Any] = {"file": path, "type": "image"}
    try:
        img = Image.open(path)
        out["format"] = img.format
        out["mode"] = img.mode
        out["size"] = img.size
        info = img.info
        out["info_keys"] = list(info.keys())
        exif_raw = img.getexif()
        if exif_raw:
            exif: Dict[str, Any] = {}
            for tag_id, value in exif_raw.items():
                tag = TAGS.get(tag_id, tag_id)
                try:
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="replace").strip("\x00")
                    exif[str(tag)] = str(value)[:500]
                except Exception:
                    exif[str(tag)] = "<unreadable>"
            out["exif"] = exif
            # GPS
            gps = exif_raw.get_ifd(0x8825) if hasattr(exif_raw, "get_ifd") else None
            if gps:
                gps_clean: Dict[str, Any] = {}
                for k, v in gps.items():
                    name = GPSTAGS.get(k, k)
                    try:
                        gps_clean[str(name)] = (
                            str(v) if not isinstance(v, (list, tuple)) else [float(x) for x in v]
                        )
                    except Exception:
                        gps_clean[str(name)] = "<unreadable>"
                out["gps"] = gps_clean
        return out
    except Exception as e:
        return {"file": path, "error": str(e)}


def _read_xml_strings(xml: bytes) -> List[str]:
    try:
        return [l.strip() for l in xml.decode("utf-8", errors="ignore").splitlines() if l.strip()]
    except Exception:
        return []


def pdf_metadata(path: str) -> Dict[str, Any]:
    """Ambil metadata PDF tanpa dependency eksternal."""
    out: Dict[str, Any] = {"file": path, "type": "pdf"}
    try:
        with open(path, "rb") as f:
            data = f.read()
        # Cari trailer & Info dict
        if b"%PDF" not in data[:1024]:
            return {"file": path, "error": "bukan file PDF"}
        out["size_bytes"] = len(data)
        out["hashes"] = file_hashes(path)
        # Cari string /Info
        for marker in (
            b"/Author",
            b"/Creator",
            b"/Producer",
            b"/Title",
            b"/Subject",
            b"/Keywords",
            b"/CreationDate",
            b"/ModDate",
        ):
            idx = data.find(marker)
            if idx != -1:
                chunk = data[idx : idx + 200]
                end = chunk.find(b"(")
                if end != -1:
                    end2 = chunk.find(b")", end)
                    if end2 != -1:
                        val = chunk[end + 1 : end2].decode("latin-1", errors="ignore")
                        out[marker.decode()[1:].lower()] = val.strip()
        return out
    except Exception as e:
        return {"file": path, "error": str(e)}


def docx_metadata(path: str) -> Dict[str, Any]:
    """Ambil metadata DOCX (DOCX = zip dengan XML)."""
    out: Dict[str, Any] = {"file": path, "type": "docx"}
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            out["entries"] = len(names)
            out["hashes"] = file_hashes(path)
            # core.xml
            if "docProps/core.xml" in names:
                core = z.read("docProps/core.xml")
                out["core_xml"] = "\n".join(_read_xml_strings(core))[:2000]
            # app.xml
            if "docProps/app.xml" in names:
                app = z.read("docProps/app.xml")
                out["app_xml"] = "\n".join(_read_xml_strings(app))[:2000]
        return out
    except Exception as e:
        return {"file": path, "error": str(e)}


def extract_metadata(path: str) -> Dict[str, Any]:
    """Dispatch ke extractor sesuai tipe file."""
    if not os.path.exists(path):
        return {"file": path, "error": "file tidak ditemukan"}
    ext = os.path.splitext(path)[1].lower()
    out: Dict[str, Any] = {
        "file": path,
        "size_bytes": os.path.getsize(path),
        "hashes": file_hashes(path),
    }
    if ext in (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".heic"):
        out.update(exif_image(path))
    elif ext == ".pdf":
        out.update(pdf_metadata(path))
    elif ext in (".docx", ".pptx", ".xlsx"):
        out.update(docx_metadata(path))
    else:
        out["note"] = "Tipe file tidak dikenali. Hanya extract hash."
    return out
