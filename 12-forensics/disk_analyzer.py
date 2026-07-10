#!/usr/bin/env python3
"""
Disk Analyzer Tool - Analisis Forensik Disk & Filesystem
Usage:
  disk_analyzer.py --device /dev/sda
  disk_analyzer.py --image disk.img --recover
  disk_analyzer.py --image disk.img --search "password"
  disk_analyzer.py --image disk.img --sector 0
"""

import argparse
import os
import re
import struct
import sys
import platform
from datetime import datetime

OS_NAME = platform.system()

BANNER = """
╔══════════════════════════════════════════════╗
║        DISK ANALYZER TOOL v1.0               ║
║   Analisis Forensik Disk & Filesystem        ║
╚══════════════════════════════════════════════╝
"""

SECTOR_SIZE = 512

PARTITION_TYPES = {
    0x00: "Kosong",
    0x01: "FAT12 (CHS)",
    0x04: "FAT16 <32M",
    0x05: "Extended",
    0x06: "FAT16 >32M",
    0x07: "NTFS / exFAT / HPFS",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16 <32M",
    0x16: "Hidden FAT16 >32M",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32",
    0x1C: "Hidden FAT32 (LBA)",
    0x1E: "Hidden FAT16 (LBA)",
    0x27: "Windows RE (hidden)",
    0x82: "Linux Swap",
    0x83: "Linux Native",
    0x84: "Hibernation",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA8: "Mac OS X",
    0xA9: "NetBSD",
    0xAB: "Mac OS X Boot",
    0xAF: "HFS+ / HFSX",
    0xB7: "BSDI",
    0xB8: "BSDI Swap",
    0xEE: "EFI GPT Protective",
    0xEF: "EFI System Partition",
    0xFD: "Linux RAID",
}

GPT_PARTITION_GUIDS = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved (MSR)",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Windows Basic Data",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM Metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM Data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Filesystem",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux Swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux /home",
    "3B8F8425-20E0-4F3B-907F-1A25A76F98E8": "Linux /boot",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux / (root-x86-64)",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
}

FILE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": (".png", "PNG Image"),
    b"\xff\xd8\xff": (".jpg", "JPEG Image"),
    b"GIF8": (".gif", "GIF Image"),
    b"%PDF": (".pdf", "PDF Document"),
    b"PK\x03\x04": (".zip", "ZIP Archive"),
    b"Rar!\x1a\x07": (".rar", "RAR Archive"),
    b"\x7fELF": ("", "ELF Executable"),
    b"MZ": ("", "PE Executable / DOS"),
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": (".doc", "OLE2 Document"),
    b"ID3": (".mp3", "MP3 Audio"),
    b"\xff\xfb": (".mp3", "MP3 Audio (alt)"),
    b"OggS": (".ogg", "OGG Audio"),
    b"RIFF": (".avi", "AVI/RIFF"),
    b"\x00\x00\x01\xba": (".mpg", "MPEG Video"),
    b"\x00\x00\x01\xb3": (".mpg", "MPEG Video (alt)"),
    b"SQLite format 3": (".db", "SQLite Database"),
    b"regf": ("", "Windows Registry Hive"),
    b"BAAD": ("", "NTFS $MFT Entry"),
    b"FILE": ("", "NTFS $MFT File Record"),
}

COMMON_SEARCH_PATTERNS = {
    "email": rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "url": rb"https?://[^\s\x00-\x1f\"'<>]+",
    "ip": rb"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "creditcard": rb"\b(?:\d[ -]*?){13,16}\b",
}


class DiskReader:
    """Pembaca disk/image universal."""
    def __init__(self, source, is_device=False):
        self.source = source
        self.is_device = is_device
        self.fh = None
        self._size = None

    def open(self):
        if self.fh:
            return
        if self.is_device:
            if OS_NAME == "Windows":
                self.fh = open(r"\\.\%s" % self.source, "rb")
            else:
                self.fh = open(self.source, "rb")
        else:
            self.fh = open(self.source, "rb")

    def close(self):
        if self.fh:
            self.fh.close()
            self.fh = None

    def read(self, offset, size):
        self.open()
        self.fh.seek(offset)
        return self.fh.read(size)

    def read_sector(self, sector_num, count=1):
        return self.read(sector_num * SECTOR_SIZE, count * SECTOR_SIZE)

    @property
    def size(self):
        if self._size is None:
            self.open()
            curr = self.fh.tell()
            self.fh.seek(0, 2)
            self._size = self.fh.tell()
            self.fh.seek(curr)
        return self._size

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()


def hexdump(data, offset=0, length=None):
    """Tampilkan hex dump standar forensik."""
    if length:
        data = data[:length]
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        result.append(f"    {offset + i:08X}  {hex_part:<48s}  |{ascii_part}|")
    return "\n".join(result)


def read_mbr(reader):
    """Baca dan parsing MBR (Master Boot Record)."""
    print("\n[*] Membaca Master Boot Record (Sektor 0)...")
    data = reader.read_sector(0)

    if len(data) < 512:
        print("[!] Data sektor terlalu pendek.")
        return

    boot_sig = data[510:512]
    if boot_sig != b"\x55\xAA":
        print(f"[!] Boot signature tidak valid: {boot_sig.hex()} (harus 55AA)")
    else:
        print("[+] Boot signature valid (0x55AA)")

    print("\n[*] Partition Table (4 entri):")
    print(f"    {'#':<3} {'Active':<8} {'Type':>5} {'Type Name':<25} {'Start LBA':>12} {'Sectors':>12} {'Size':>12}")
    print("    " + "-" * 85)

    found_partitions = []
    for i in range(4):
        offset = 446 + i * 16
        entry = data[offset : offset + 16]
        if len(entry) < 16:
            continue

        boot_flag = entry[0]
        start_chs = entry[1:4]
        part_type = entry[4]
        end_chs = entry[5:8]
        start_lba = struct.unpack("<I", entry[8:12])[0]
        num_sectors = struct.unpack("<I", entry[12:16])[0]

        if part_type == 0:
            continue

        type_name = PARTITION_TYPES.get(part_type, f"Unknown (0x{part_type:02X})")
        active = "Yes" if boot_flag == 0x80 else "No"
        size_mb = (num_sectors * SECTOR_SIZE) / (1024 * 1024)

        print(f"    {i+1:<3} {active:<8} 0x{part_type:02X}  {type_name:<25} {start_lba:>12} {num_sectors:>12} {size_mb:>9.1f} MB")

        found_partitions.append({
            "index": i + 1,
            "active": boot_flag == 0x80,
            "type": part_type,
            "type_name": type_name,
            "start_lba": start_lba,
            "sectors": num_sectors,
            "size_mb": size_mb,
        })

    if not found_partitions:
        print("    [*] Tidak ada partisi di MBR (mungkin disk GPT).")

    return found_partitions


def read_gpt(reader):
    """Baca dan parsing GPT (GUID Partition Table)."""
    print("\n[*] Memeriksa GPT header (LBA 1)...")
    try:
        data = reader.read_sector(1)
    except Exception as e:
        print(f"[!] Gagal membaca LBA 1: {e}")
        return

    if data[:8] != b"EFI PART":
        print("[*] GPT header tidak ditemukan (bukan disk GPT).")
        return

    print("[+] GPT header ditemukan!")

    revision = struct.unpack("<I", data[8:12])[0]
    header_size = struct.unpack("<I", data[12:16])[0]
    header_crc = struct.unpack("<I", data[16:20])[0]
    my_lba = struct.unpack("<Q", data[24:32])[0]
    first_usable = struct.unpack("<Q", data[40:48])[0]
    last_usable = struct.unpack("<Q", data[48:56])[0]
    disk_guid_bytes = data[56:72]
    part_entry_lba = struct.unpack("<Q", data[72:80])[0]
    num_entries = struct.unpack("<I", data[80:84])[0]
    entry_size = struct.unpack("<I", data[84:88])[0]

    disk_guid = str_uuid(disk_guid_bytes)
    disk_size_gb = (reader.size) / (1024**3)

    print(f"[*] Revisi GPT: {revision}")
    print(f"[*] Header size: {header_size} bytes")
    print(f"[*] My LBA: {my_lba}")
    print(f"[*] First usable LBA: {first_usable}")
    print(f"[*] Last usable LBA: {last_usable}")
    print(f"[*] Disk GUID: {disk_guid}")
    print(f"[*] Part entries start LBA: {part_entry_lba}")
    print(f"[*] Num entries: {num_entries} x {entry_size} bytes")
    print(f"[*] Perkiraan ukuran disk: {disk_size_gb:.1f} GB")

    print(f"\n[*] GPT Partitions:")
    print(f"    {'#':<3} {'Type':<45} {'Partition GUID':<38} {'Start LBA':>12} {'End LBA':>12} {'Size':>10}")
    print("    " + "-" * 130)

    entry_data = reader.read(part_entry_lba * SECTOR_SIZE, num_entries * entry_size)
    part_num = 0

    for i in range(0, len(entry_data), entry_size):
        entry = entry_data[i : i + entry_size]
        if len(entry) < 56:
            continue

        type_guid = str_uuid(entry[0:16])
        part_guid = str_uuid(entry[16:32])
        first_lba = struct.unpack("<Q", entry[32:40])[0]
        last_lba = struct.unpack("<Q", entry[40:48])[0]
        attr = struct.unpack("<Q", entry[48:56])[0]

        if first_lba == 0 and last_lba == 0:
            continue

        part_num += 1
        type_name = GPT_PARTITION_GUIDS.get(type_guid, "")
        size_mb = ((last_lba - first_lba + 1) * SECTOR_SIZE) / (1024 * 1024)
        name_utf16 = entry[56:128]
        try:
            name = name_utf16.decode("utf-16-le").rstrip("\x00")
        except Exception:
            name = ""

        display_type = f"{type_name} ({type_guid[:16]}...)" if type_name else type_guid
        print(f"    {part_num:<3} {display_type:<45} {part_guid:<38} {first_lba:>12} {last_lba:>12} {size_mb:>7.1f} MB"
              + (f"  [{name}]" if name else ""))


def str_uuid(data):
    """Format bytes ke UUID string."""
    if len(data) < 16:
        return "INVALID"
    return "%08X-%04X-%04X-%04X-%012X" % struct.unpack("<IHHI", data[:16])


def read_boot_sector(reader, lba):
    """Baca dan tampilkan boot sector."""
    print(f"\n[*] Membaca boot sector di LBA {lba}...")
    data = reader.read_sector(lba)

    print(f"\n[*] Boot Sector hex dump (offset 0x{lba * SECTOR_SIZE:X}):")
    print(hexdump(data, offset=lba * SECTOR_SIZE))

    if data[:3] == b"\xEB\x52\x90" or data[:3] == b"\xEB\x58\x90":
        print("[+] Signature: NTFS Boot Sector")
    elif data[:3] == b"\xEB\x3C\x90":
        print("[+] Signature: FAT Boot Sector (jmp near)")
    elif data[:3] == b"\xE9\x3C\x90":
        print("[+] Signature: FAT32 Boot Sector")
    elif data[3:11] == b"NTFS    ":
        print("[+] Signature: NTFS (OEM ID)")
    elif data[54:62] == b"FAT12   " or data[54:62] == b"FAT16   ":
        print("[+] Signature: FAT12/16 (OEM)")
    elif data[82:90] == b"FAT32   ":
        print("[+] Signature: FAT32 (OEM)")

    oem_id = data[3:11].decode("ascii", errors="replace").strip()
    print(f"[*] OEM ID: {oem_id}")
    print(f"[*] Bytes per sector: {struct.unpack('<H', data[11:13])[0]}")
    print(f"[*] Sectors per cluster: {data[13]}")
    print(f"[*] Reserved sectors: {struct.unpack('<H', data[14:16])[0]}")


def analyze_ntfs(reader, start_lba):
    """Analisis NTFS volume — $MFT entries."""
    print(f"\n[*] Menganalisis NTFS volume di LBA {start_lba}...")
    boot = reader.read_sector(start_lba)

    bytes_per_sector = struct.unpack("<H", boot[11:13])[0]
    sectors_per_cluster = boot[13]
    cluster_size = bytes_per_sector * sectors_per_cluster
    mft_start_cluster = struct.unpack("<q", boot[48:56])[0]
    mft_entry_size_raw = struct.unpack("<i", boot[64:68])[0]
    if mft_entry_size_raw > 0:
        mft_entry_size = mft_entry_size_raw * sectors_per_cluster * bytes_per_sector
    else:
        mft_entry_size = 2 ** abs(mft_entry_size_raw)

    print(f"[*] Bytes per sector: {bytes_per_sector}")
    print(f"[*] Sectors per cluster: {sectors_per_cluster}")
    print(f"[*] Cluster size: {cluster_size} bytes")
    print(f"[*] $MFT start cluster: {mft_start_cluster}")
    print(f"[*] MFT entry size: {mft_entry_size} bytes")

    mft_offset = start_lba * bytes_per_sector + mft_start_cluster * cluster_size
    print(f"[*] $MFT offset: {mft_offset} (0x{mft_offset:X})")

    try:
        mft_data = reader.read(mft_offset, mft_entry_size * 16)
        print(f"\n[*] $MFT entries pertama (max 16):")
        for i in range(0, min(len(mft_data), mft_entry_size * 16), mft_entry_size):
            entry = mft_data[i : i + mft_entry_size]
            if len(entry) < 48:
                continue

            signature = entry[:4]
            if signature not in (b"FILE", b"BAAD"):
                continue

            seq = struct.unpack("<H", entry[16:18])[0]
            link_count = struct.unpack("<H", entry[18:20])[0]
            attr_offset = struct.unpack("<H", entry[20:22])[0]
            flags = struct.unpack("<H", entry[22:24])[0]

            in_use = "IN USE" if (flags & 0x0001) else "FREE"
            is_dir = "DIR " if (flags & 0x0002) else "FILE"

            fn_attr = entry[attr_offset:]
            filename = _extract_ntfs_filename(fn_attr)
            if filename:
                print(f"    [{in_use}] [{is_dir}] Seq={seq} Links={link_count}  {filename}")

    except Exception as e:
        print(f"[!] Gagal membaca $MFT: {e}")


def _extract_ntfs_filename(data):
    """Ekstrak nama file dari atribut NTFS $FILE_NAME."""
    pos = 0
    while pos < len(data) - 4:
        attr_type = struct.unpack("<I", data[pos : pos + 4])[0]
        attr_len = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
        if attr_len == 0 or pos + attr_len > len(data):
            break
        if attr_type == 0x30:
            name_len = data[pos + 0x58]
            name_offset = pos + 0x5A
            try:
                return data[name_offset : name_offset + name_len * 2].decode("utf-16-le")
            except Exception:
                return "<decode error>"
        if attr_type == 0xFFFFFFFF:
            break
        pos += attr_len
    return None


def recover_files(reader):
    """Cari file signature di unallocated space (carving)."""
    print("\n[*] Mode recovery — mencari signature file...")
    print("[*] Memindai seluruh disk/image... (ini bisa lama)")

    disk_size = reader.size
    chunk_size = 1024 * 1024 * 8
    reported = set()

    try:
        offset = 0
        while offset < disk_size:
            chunk = reader.read(offset, min(chunk_size, disk_size - offset))
            if not chunk:
                break

            for sig, (ext, desc) in FILE_SIGNATURES.items():
                pos = 0
                while True:
                    idx = chunk.find(sig, pos)
                    if idx == -1:
                        break
                    abs_offset = offset + idx
                    sector = abs_offset // SECTOR_SIZE
                    if sector not in reported:
                        reported.add(sector)
                        print(f"    [+] {desc} ({ext}) ditemukan di offset 0x{abs_offset:012X} (LBA {sector})")
                    pos = idx + 1

            progress = min(100, (offset / disk_size) * 100)
            print(f"\r[*] Progress: {progress:.1f}% ({offset / (1024**2):.0f} MB / {disk_size / (1024**2):.0f} MB)",
                  end="", flush=True)
            offset += len(chunk)

        print()
        print(f"[+] Pemindaian recovery selesai. {len(reported)} signature unik ditemukan.")

    except Exception as e:
        print(f"\n[!] Gagal memindai: {e}")


def search_pattern(reader, pattern):
    """Cari pattern di seluruh disk/image."""
    print(f"\n[*] Mencari pattern: {pattern}")

    if pattern.lower() in COMMON_SEARCH_PATTERNS:
        regex = COMMON_SEARCH_PATTERNS[pattern.lower()]
        print(f"[*] Menggunakan regex bawaan untuk '{pattern}'")
    else:
        regex = pattern.encode("utf-8", errors="replace")

    if hasattr(regex, "decode"):
        compiled = re.compile(regex)
    else:
        compiled = re.compile(regex if isinstance(regex, bytes) else regex.encode())

    disk_size = reader.size
    chunk_size = 1024 * 1024 * 4
    found_count = 0
    context_size = 60

    try:
        offset = 0
        while offset < disk_size:
            chunk = reader.read(offset, min(chunk_size, disk_size - offset))
            if not chunk:
                break

            for match in compiled.finditer(chunk):
                abs_offset = offset + match.start()
                sector = abs_offset // SECTOR_SIZE
                val = match.group()
                try:
                    context = chunk[
                        max(0, match.start() - context_size) :
                        min(len(chunk), match.end() + context_size)
                    ]
                    context_str = context.decode("utf-8", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
                except Exception:
                    context_str = repr(context)[:100]

                print(f"    LBA {sector:>10} | offset 0x{abs_offset:012X} | {context_str[:150]}")
                found_count += 1

                if found_count >= 500:
                    print(f"    ... Mencapai limit 500. Hentikan pencarian.")
                    offset = disk_size
                    break

            offset += len(chunk)
            progress = min(100, (offset / disk_size) * 100)
            print(f"\r[*] Progress: {progress:.1f}%", end="", flush=True)

        print()
        print(f"[+] Pencarian selesai. {found_count} hasil ditemukan.")

    except Exception as e:
        print(f"\n[!] Gagal mencari: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Disk Analyzer Tool — Analisis Forensik Disk & Filesystem",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s --device /dev/sda
  %(prog)s --image disk.img --recover
  %(prog)s --image disk.img --search email
  %(prog)s --image disk.img --sector 63
        """,
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--device", type=str, help="Device disk fisik (Linux: /dev/sda, Win: PhysicalDrive0)")
    source_group.add_argument("--image", type=str, help="File image disk (.img, .dd, .e01 raw, .vhd)")

    parser.add_argument("--sector", type=int, default=0, help="Baca sektor tertentu (default: 0)")
    parser.add_argument("--recover", action="store_true", help="Mode recovery — cari signature file")
    parser.add_argument("--search", type=str, help="Cari pattern/regex di disk (atau: email, url, ip, creditcard)")

    args = parser.parse_args()

    print(BANNER)
    print(f"[*] OS: {OS_NAME}")
    print(f"[*] Waktu: {datetime.now():%Y-%m-%d %H:%M:%S}")

    source = args.device or args.image
    is_device = bool(args.device)

    print(f"[*] Sumber: {source}")
    print(f"[*] Mode akses: {'Device fisik' if is_device else 'File image'}")

    if is_device and OS_NAME == "Windows":
        print("[!] Akses disk fisik di Windows butuh Administrator.")
        print("[!] Gunakan path seperti: PhysicalDrive0, \\\\.\\C:")

    reader = DiskReader(source, is_device)

    try:
        if is_device:
            print(f"[*] Ukuran device: {reader.size:,} bytes ({reader.size / (1024**3):.2f} GB)")

        if args.recover:
            recover_files(reader)

        elif args.search:
            search_pattern(reader, args.search)

        elif args.sector > 0:
            read_boot_sector(reader, args.sector)

        else:
            print(f"[*] Ukuran: {reader.size:,} bytes ({reader.size / (1024**3):.2f} GB)")

            mbr = read_mbr(reader)
            read_gpt(reader)

            if mbr:
                for part in mbr:
                    if part["type"] == 0x07:
                        read_boot_sector(reader, part["start_lba"])
                        analyze_ntfs(reader, part["start_lba"])
                        break

    except PermissionError:
        print("[!] Akses ditolak. Jalankan sebagai Administrator/root.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        reader.close()

    print(f"\n[+] Selesai.")


if __name__ == "__main__":
    main()
