#!/usr/bin/env python3
"""
Steganalysis Detector — Detect hidden data in images.
LSB analysis, EOF marker detection, metadata check, histogram analysis,
chi-square test, string extraction.

Usage: python stego_detector.py --file suspicious.png
"""

import argparse
import re
import struct
import sys
from collections import Counter
from pathlib import Path

SUSPICIOUS_STRINGS = [
    r"https?://[\w./?&=%-]+",
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"(password|passwd|secret|key|token|api_key)\s*[:=]",
    r"(cmd\.exe|powershell|/bin/bash|/bin/sh)",
    r"SELECT\s+.*FROM|INSERT\s+INTO|DROP\s+TABLE",
    r"<script|<iframe|eval\s*\(|document\.cookie",
]

EOF_MARKERS = {
    b"PK\x03\x04": "ZIP archive",
    b"PK\x05\x06": "ZIP archive (EOCD)",
    b"PK\x07\x08": "ZIP archive (spanned)",
    b"Rar!\x1a\x07": "RAR archive (v4)",
    b"Rar!\x1a\x07\x00": "RAR archive (v5)",
    b"7z\xbc\xaf'\x1c": "7-Zip archive",
    b"%PDF": "PDF document",
    b"\x1f\x8b\x08": "Gzip file",
    b"BZh": "Bzip2 file",
    b"\x89PNG\r\n\x1a\n": "PNG image (embedded)",
    b"\xff\xd8\xff": "JPEG image (embedded)",
    b"GIF8": "GIF image (embedded)",
    b"BM": "Windows Bitmap (embedded)",
}


def detect_format(filepath):
    suffix = Path(filepath).suffix.lower()
    with open(filepath, "rb") as f:
        header = f.read(16)

    if header.startswith(b"\x89PNG"):
        return "PNG"
    if header.startswith(b"\xff\xd8"):
        return "JPEG"
    if header[:2] == b"BM":
        return "BMP"
    if header[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"

    return suffix.lstrip(".").upper()


def get_image_dimensions(filepath, fmt):
    with open(filepath, "rb") as f:
        if fmt == "PNG":
            f.seek(16)
            w = struct.unpack(">I", f.read(4))[0]
            h = struct.unpack(">I", f.read(4))[0]
            return w, h
        elif fmt == "BMP":
            f.seek(18)
            w = struct.unpack("<i", f.read(4))[0]
            h = struct.unpack("<i", f.read(4))[0]
            return abs(w), abs(h)
        elif fmt == "JPEG":
            f.seek(2)
            while True:
                marker = f.read(2)
                if marker != b"\xff\xc0":
                    size = struct.unpack(">H", f.read(2))[0]
                    f.seek(size - 2, 1)
                else:
                    f.read(1)
                    h = struct.unpack(">H", f.read(2))[0]
                    w = struct.unpack(">H", f.read(2))[0]
                    return w, h

    return 0, 0


def analyze_lsb(filepath, fmt):
    findings = []

    try:
        from PIL import Image
    except ImportError:
        return [{"type": "error", "msg": "Pillow required: pip install pillow"}]

    img = Image.open(filepath)
    if img.mode != "RGB":
        img = img.convert("RGB")

    pixels = list(img.getdata())

    lsb_bytes = []
    byte_bits = []
    for pixel in pixels:
        for channel in pixel:
            byte_bits.append(str(channel & 1))
            if len(byte_bits) == 8:
                lsb_bytes.append(int("".join(byte_bits), 2))
                byte_bits = []

    total_bytes = len(lsb_bytes)
    byte_counts = Counter(lsb_bytes)

    printable_count = sum(v for k, v in byte_counts.items() if 32 <= k <= 126)
    printable_ratio = printable_count / max(total_bytes, 1)

    findings.append(
        {
            "type": "lsb",
            "lsb_bytes_analyzed": total_bytes,
            "printable_ratio": round(printable_ratio * 100, 2),
            "unique_bytes": len(byte_counts),
            "top_bytes": byte_counts.most_common(10),
        }
    )

    if printable_ratio > 0.70:
        findings[-1]["flag"] = "High printable character ratio in LSB — possible text hidden"
    elif printable_ratio < 0.20:
        findings[-1]["flag"] = "Low printable ratio — may contain encrypted/compressed payload"

    return findings


def chi_square_test(filepath, fmt):
    try:
        from PIL import Image
    except ImportError:
        return None

    img = Image.open(filepath)
    if img.mode != "RGB":
        img = img.convert("RGB")

    pixels = list(img.getdata())

    all_lsbs = []
    for pixel in pixels:
        for channel in pixel:
            all_lsbs.append(channel & 1)

    chunk_size = 128
    deviations = []

    for i in range(0, len(all_lsbs), chunk_size):
        chunk = all_lsbs[i : i + chunk_size]
        if len(chunk) < chunk_size:
            continue

        zeros = sum(1 for b in chunk if b == 0)
        ones = len(chunk) - zeros
        expected = len(chunk) / 2
        chi_sq = (
            ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected if expected > 0 else 0
        )
        deviations.append(chi_sq)

    avg_chi = sum(deviations) / max(len(deviations), 1)

    result = {
        "type": "chi_square",
        "chunks_analyzed": len(deviations),
        "avg_chi_square": round(avg_chi, 4),
    }

    if avg_chi < 0.5:
        result["verdict"] = "LSB distribution matches expected random — clean"
    elif avg_chi < 2.0:
        result["verdict"] = "Slight deviation from expected — needs further analysis"
    elif avg_chi < 5.0:
        result["verdict"] = "Significant LSB anomaly — likely steganography"
    else:
        result["verdict"] = "Strong LSB anomaly — very likely steganography"

    return result


def analyze_histogram(filepath, fmt):
    try:
        from PIL import Image
    except ImportError:
        return None

    img = Image.open(filepath)
    if img.mode != "RGB":
        img = img.convert("RGB")

    pixels = list(img.getdata())
    hist_r = Counter()
    hist_g = Counter()
    hist_b = Counter()

    for r, g, b in pixels:
        hist_r[r] += 1
        hist_g[g] += 1
        hist_b[b] += 1

    def find_spikes(histogram, channel_name):
        if not histogram:
            return []
        avg = sum(histogram.values()) / len(histogram)
        spikes = []
        for val, count in histogram.items():
            if count > avg * 3:
                spikes.append(
                    {
                        "value": val,
                        "count": count,
                        "channel": channel_name,
                        "ratio": round(count / avg, 2),
                    }
                )
        return spikes

    spikes = []
    spikes.extend(find_spikes(hist_r, "R"))
    spikes.extend(find_spikes(hist_g, "G"))
    spikes.extend(find_spikes(hist_b, "B"))

    even_odd_r = sum(1 for v in hist_r if v % 2 == 0)
    odd_r = len(hist_r) - even_odd_r

    return {
        "type": "histogram",
        "spikes_found": len(spikes),
        "spikes": spikes[:10],
        "even_values": even_odd_r,
        "odd_values": odd_r,
        "lsb_pair_bias": round((even_odd_r - odd_r) / max((even_odd_r + odd_r), 1) * 100, 2),
    }


def scan_eof(filepath, fmt):
    findings = []
    img_end = 0

    with open(filepath, "rb") as f:
        data = f.read()

    if fmt == "PNG":
        marker = b"IEND\xaeB`\x82"
        pos = data.find(marker)
        if pos != -1:
            img_end = pos + len(marker)
    elif fmt == "JPEG":
        pos = data.find(b"\xff\xd9")
        if pos != -1:
            img_end = pos + 2

    if img_end > 0 and img_end < len(data):
        trailing = data[img_end:]
        trailing_size = len(trailing)
        findings.append(
            {
                "type": "eof",
                "bytes_after_image": trailing_size,
                "found_payloads": [],
            }
        )

        for signature, desc in EOF_MARKERS.items():
            offset = trailing.find(signature)
            if offset != -1:
                findings[-1]["found_payloads"].append(
                    {
                        "offset": offset,
                        "type": desc,
                        "size": trailing_size - offset,
                    }
                )

    return findings


def extract_strings(filepath, min_len=4):
    with open(filepath, "rb") as f:
        data = f.read()

    printable_chunks = []
    current = b""
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                printable_chunks.append(current.decode("ascii"))
            current = b""
    if len(current) >= min_len:
        printable_chunks.append(current.decode("ascii"))

    suspicious = []
    for s in printable_chunks:
        if len(s) > 200:
            continue
        for pattern in SUSPICIOUS_STRINGS:
            if re.search(pattern, s, re.IGNORECASE):
                suspicious.append(s)
                break

    return {
        "type": "strings",
        "total_ascii_strings": len(printable_chunks),
        "suspicious_strings": suspicious[:30],
    }


def check_metadata(filepath):
    findings = []
    suspicious_exif = []

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        return [{"type": "exif", "msg": "Pillow not available"}]

    img = Image.open(filepath)
    exif_raw = img._getexif()
    if exif_raw:
        for tag_id, value in exif_raw.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            val_str = str(value)

            if (
                any(
                    kw in tag_name.lower() for kw in ("comment", "usercomment", "image_description")
                )
                and len(val_str) > 100
            ):
                suspicious_exif.append(
                    {"tag": tag_name, "value_preview": val_str[:120], "length": len(val_str)}
                )

            if len(val_str) > 500:
                suspicious_exif.append(
                    {"tag": tag_name, "value_preview": val_str[:120], "length": len(val_str)}
                )

    if suspicious_exif:
        findings.append(
            {
                "type": "exif",
                "suspicious_tags": suspicious_exif,
            }
        )

    try:
        if hasattr(img, "text") and img.text:
            for key, val in img.text.items():
                if len(str(val)) > 200:
                    findings.append(
                        {
                            "type": "png_text",
                            "key": key,
                            "value_preview": str(val)[:120],
                            "length": len(str(val)),
                        }
                    )
    except Exception:
        pass

    if not findings:
        findings.append({"type": "exif", "suspicious_tags": []})

    return findings


def verdict(all_findings):
    score = 0
    evidence = []

    for f in all_findings:
        if f.get("type") == "lsb":
            ratio = f.get("printable_ratio", 0)
            if ratio > 70:
                score += 30
                evidence.append(f"LSB printable ratio high ({ratio}%) — text hidden in LSB")
            elif ratio < 15:
                score += 15
                evidence.append(
                    f"LSB printable ratio very low ({ratio}%) — possible encrypted payload"
                )

        if f.get("type") == "chi_square":
            avg = f.get("avg_chi_square", 0)
            if avg > 5:
                score += 40
                evidence.append(f"Chi-square anomaly (avg={avg}) — LSB steganography detected")
            elif avg > 2:
                score += 20
                evidence.append(f"Chi-square deviation (avg={avg}) — possible LSB steganography")
            elif avg < 0.5:
                evidence.append("Chi-square test normal — LSB likely clean")

        if f.get("type") == "histogram":
            spikes = f.get("spikes_found", 0)
            if spikes > 3:
                score += 10
                evidence.append(f"Color histogram spikes ({spikes}) — possible LSB manipulation")
            bias = f.get("lsb_pair_bias", 0)
            if abs(bias) > 20:
                score += 20
                evidence.append(f"LSB pair bias ({bias}%) — data hidden in pixel LSBs")

        if f.get("type") == "eof":
            payloads = f.get("found_payloads", [])
            if payloads:
                score += 50
                for p in payloads:
                    evidence.append(f"Hidden file after image: {p['type']} at offset {p['offset']}")

        if f.get("type") == "exif":
            tags = f.get("suspicious_tags", [])
            if tags:
                score += 15
                for t in tags:
                    evidence.append(f"Suspicious EXIF tag '{t['tag']}' ({t['length']} chars)")

        if f.get("type") == "strings":
            sus = f.get("suspicious_strings", [])
            if sus:
                score += 10
                evidence.append(f"Suspicious strings found ({len(sus)} matches)")

    score = min(score, 100)
    if score >= 60:
        label = "LIKELY STEGO"
    elif score >= 30:
        label = "SUSPICIOUS"
    else:
        label = "CLEAN"

    return label, score, evidence


def main():
    parser = argparse.ArgumentParser(
        description="Stego Detector — Detect hidden data in images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python stego_detector.py --file suspicious.png
  python stego_detector.py --file hidden.jpg
        """,
    )
    parser.add_argument("--file", "-f", required=True, help="Image file to analyze")

    args = parser.parse_args()

    if not Path(args.file).exists():
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    fmt = detect_format(args.file)
    w, h = get_image_dimensions(args.file, fmt)

    print("\n" + "=" * 70)
    print("  STEGO DETECTOR — Steganalysis Report")
    print("=" * 70)
    print(f"\n  File   : {args.file}")
    print(f"  Format : {fmt}")
    if w and h:
        print(f"  Size   : {w}x{h} pixels")
    print(f"  Path   : {Path(args.file).absolute()}")

    all_findings = []

    print(f"\n{'─' * 70}")
    print("  [1] LSB Analysis")
    print(f"{'─' * 70}")
    lsb_results = analyze_lsb(args.file, fmt)
    all_findings.extend(lsb_results)
    for f in lsb_results:
        if f["type"] == "lsb":
            print(f"  LSB bytes analyzed : {f['lsb_bytes_analyzed']}")
            print(f"  Printable ratio    : {f['printable_ratio']}%")
            print(f"  Unique bytes       : {f['unique_bytes']}")
            top = f["top_bytes"][:5]
            print(f"  Top byte values    : {top}")
            if f.get("flag"):
                print(f"  [!] {f['flag']}")

    print(f"\n{'─' * 70}")
    print("  [2] Chi-Square Test on LSB")
    print(f"{'─' * 70}")
    chi_result = chi_square_test(args.file, fmt)
    if chi_result:
        all_findings.append(chi_result)
        print(f"  Chunks analyzed  : {chi_result['chunks_analyzed']}")
        print(f"  Avg chi-square   : {chi_result['avg_chi_square']}")
        print(f"  Verdict          : {chi_result['verdict']}")

    print(f"\n{'─' * 70}")
    print("  [3] Histogram Analysis")
    print(f"{'─' * 70}")
    hist_result = analyze_histogram(args.file, fmt)
    if hist_result:
        all_findings.append(hist_result)
        print(f"  Color spikes      : {hist_result['spikes_found']}")
        print(f"  LSB pair bias     : {hist_result['lsb_pair_bias']}%")
        for s in hist_result["spikes"]:
            print(
                f"    Channel {s['channel']} value {s['value']} ({s['count']} pixels, {s['ratio']}x avg)"
            )

    print(f"\n{'─' * 70}")
    print("  [4] EOF Marker Detection")
    print(f"{'─' * 70}")
    eof_results = scan_eof(args.file, fmt)
    all_findings.extend(eof_results)
    for f in eof_results:
        if f["type"] == "eof":
            print(f"  Bytes after image : {f['bytes_after_image']}")
            if f["found_payloads"]:
                for p in f["found_payloads"]:
                    print(f"  [!] Hidden {p['type']} at offset {p['offset']} ({p['size']} bytes)")
            else:
                print(f"  No hidden payloads detected after image EOF")

    print(f"\n{'─' * 70}")
    print("  [5] Metadata Check")
    print(f"{'─' * 70}")
    meta_results = check_metadata(args.file)
    all_findings.extend(meta_results)
    for f in meta_results:
        if f["type"] == "exif":
            if f.get("suspicious_tags"):
                for t in f["suspicious_tags"]:
                    print(f"  [!] Suspicious tag: {t['tag']} ({t['length']} chars)")
                    print(f"      Preview: {t['value_preview']}")
            else:
                print(f"  Metadata clean")
        elif f["type"] == "png_text":
            print(f"  [!] Large PNG text chunk: {f['key']} ({f['length']} chars)")

    print(f"\n{'─' * 70}")
    print("  [6] String Extraction")
    print(f"{'─' * 70}")
    str_results = extract_strings(args.file)
    all_findings.append(str_results)
    print(f"  ASCII strings     : {str_results['total_ascii_strings']}")
    if str_results["suspicious_strings"]:
        print(f"  [!] Suspicious strings found ({len(str_results['suspicious_strings'])}):")
        for s in str_results["suspicious_strings"]:
            print(f"      {s[:120]}")
    else:
        print(f"  No suspicious strings found")

    print(f"\n{'═' * 70}")
    label, confidence, evidence = verdict(all_findings)
    print(f"  VERDICT: {label}")
    print(f"  CONFIDENCE: {confidence}%")
    print(f"  EVIDENCE:")
    for e in evidence:
        print(f"    - {e}")
    print(f"{'═' * 70}\n")


if __name__ == "__main__":
    main()
