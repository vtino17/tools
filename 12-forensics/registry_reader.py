#!/usr/bin/env python3
"""
Registry Reader Tool - Pembaca Forensik Windows Registry
Usage:
  registry_reader.py --hive SAM --all
  registry_reader.py --hive SOFTWARE --key "Microsoft\\Windows\\CurrentVersion\\Run"
  registry_reader.py --hive SYSTEM --all --output report.json
  registry_reader.py --hive NTUSER.DAT --key "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
"""

import argparse
import json
import os
import struct
import sys
from datetime import datetime, timezone

BANNER = """
+==============================================+
|      REGISTRY READER TOOL v1.0               |
|   Pembaca Forensik Windows Registry Hive     |
+==============================================+
"""

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11
REG_NONE = 0

VALUE_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BE",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

KEY_INTEREST_PATHS = {
    "SAM": [
        ("SAM\\Domains\\Account\\Users", "Informasi User Account"),
        ("SAM\\Domains\\Account\\Users\\Names", "Daftar Nama User"),
    ],
    "SYSTEM": [
        ("ControlSet001\\Services", "Services & Drivers"),
        ("ControlSet001\\Control\\Session Manager\\Memory Management", "Konfigurasi Memori"),
    ],
    "SOFTWARE": [
        ("Microsoft\\Windows\\CurrentVersion\\Run", "Startup - CurrentVersion\\Run"),
        ("Microsoft\\Windows\\CurrentVersion\\RunOnce", "Startup - RunOnce"),
        ("Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "Startup - Policies"),
        ("Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "TypedPaths (URL history)"),
        ("Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "RecentDocs"),
        ("Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Winlogon Config"),
        ("Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs"),
    ],
    "NTUSER.DAT": [
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Startup (User)"),
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "TypedPaths"),
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "RecentDocs"),
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "RunMRU"),
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", "USB History"),
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "Internet Settings"),
    ],
    "USRCLASS.DAT": [
        ("Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "MuiCache"),
        (
            "Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository",
            "App Repository",
        ),
    ],
}

NETWORK_KEYS = {
    "SOFTWARE": [
        ("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", "Network Profiles"),
        (
            "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
            "Networks (Unmanaged)",
        ),
        (
            "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed",
            "Networks (Managed)",
        ),
    ],
}

WIRELESS_KEYS = {
    "SOFTWARE": [
        ("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures", "Wireless Profiles"),
    ],
}


def guess_hive_type(filename):
    """Tebak tipe hive dari nama file."""
    basename = os.path.basename(filename).upper()
    if basename == "SAM" or basename.startswith("SAM"):
        return "SAM"
    elif basename == "SYSTEM" or basename.startswith("SYSTEM"):
        return "SYSTEM"
    elif basename == "SOFTWARE" or basename.startswith("SOFTWARE"):
        return "SOFTWARE"
    elif basename == "SECURITY" or basename.startswith("SECURITY"):
        return "SECURITY"
    elif basename == "DEFAULT" or basename.startswith("DEFAULT"):
        return "DEFAULT"
    elif basename == "NTUSER.DAT" or basename.startswith("NTUSER"):
        return "NTUSER.DAT"
    elif basename == "USRCLASS.DAT" or basename.startswith("USRCLASS"):
        return "USRCLASS.DAT"
    elif basename.startswith("BCDBACKGROUND"):
        return "BCD"
    elif basename.startswith("COMPONENTS"):
        return "COMPONENTS"
    return "UNKNOWN"


class RegHive:
    """Parser registry hive file format."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.fh = None
        self.root_key = None
        self.hive_type = guess_hive_type(filepath)

    def open(self):
        self.fh = open(self.filepath, "rb")
        self._validate_header()

    def close(self):
        if self.fh:
            self.fh.close()
            self.fh = None

    def _validate_header(self):
        """Validasi header REGF hive."""
        self.fh.seek(0)
        header = self.fh.read(4)
        if header != b"regf":
            raise ValueError(f"Invalid registry hive header: {header!r}, expected b'regf'")

        self.fh.seek(4)
        seq1, seq2 = struct.unpack("<II", self.fh.read(8))
        timestamp = struct.unpack("<Q", self.fh.read(8))[0]
        ts = filetime_to_datetime(timestamp)
        major, minor = struct.unpack("<II", self.fh.read(8))
        hive_name_offset = 0x30

        self.fh.seek(12)
        root_cell_offset = struct.unpack("<I", self.fh.read(4))[0] + 0x1000

        self.fh.seek(0x30)
        hive_name = ""
        c = self.fh.read(2)
        while c != b"\x00\x00":
            try:
                hive_name += c.decode("utf-16-le")
            except Exception:
                break
            c = self.fh.read(2)

        print(f"[*] Nama Hive: {hive_name}")
        print(f"[*] Urutan: {seq1}/{seq2}")
        print(f"[*] Timestamp: {ts}")
        print(f"[*] Versi: {major}.{minor}")
        print(f"[*] Root offset: 0x{root_cell_offset:X}")

        self._root_offset = root_cell_offset
        self._hive_name = hive_name
        self._timestamp = ts

    def _read_cell(self, offset):
        if offset == 0xFFFFFFFF or offset < 0x1000:
            return None, None, None, 0
        self.fh.seek(offset)
        size_raw = self.fh.read(4)
        if len(size_raw) < 4:
            return None, None, None, 0
        size = struct.unpack("<i", size_raw)[0]
        if size > 0:
            data_offset = offset + 4
            data_size = size
        else:
            data_offset = offset + 4
            data_size = abs(size)

        self.fh.seek(data_offset)
        data = self.fh.read(data_size)
        return data_offset, data_size, data, abs(size)

    def _parse_nk(self, offset):
        """Parse NK (Node Key) record."""
        self.fh.seek(offset)
        raw = self.fh.read(80)
        if len(raw) < 76:
            return None

        sig = struct.unpack("<H", raw[0:2])[0]
        if sig != 0x6B6E:
            return None

        flags = struct.unpack("<H", raw[2:4])[0]
        timestamp = filetime_to_datetime(struct.unpack("<Q", raw[4:12])[0])
        parent_offset = struct.unpack("<i", raw[16:20])[0] + 0x1000
        num_subkeys = struct.unpack("<I", raw[20:24])[0]
        subkeys_list_offset = struct.unpack("<i", raw[24:28])[0]
        num_values = struct.unpack("<I", raw[36:40])[0]
        values_list_offset = struct.unpack("<i", raw[40:44])[0]
        sk_offset = struct.unpack("<i", raw[44:48])[0] + 0x1000
        name_len = struct.unpack("<H", raw[76:78])[0]
        name_offset = offset + 4 + 76

        self.fh.seek(name_offset)
        name = self.fh.read(name_len).decode("utf-16-le", errors="replace")

        is_root = bool(flags & 0x0040)

        return {
            "offset": offset,
            "name": name,
            "timestamp": timestamp,
            "num_subkeys": num_subkeys,
            "num_values": num_values,
            "parent_offset": parent_offset if not is_root else None,
            "subkeys_list_offset": (
                subkeys_list_offset + 0x1000 if subkeys_list_offset != -1 else None
            ),
            "values_list_offset": values_list_offset + 0x1000 if values_list_offset != -1 else None,
            "sk_offset": sk_offset,
            "is_root": is_root,
        }

    def _parse_vk(self, offset):
        """Parse VK (Value Key) record."""
        if offset == 0xFFFFFFFF:
            return None

        self.fh.seek(offset)
        raw = self.fh.read(24)
        if len(raw) < 20:
            return None

        sig = struct.unpack("<H", raw[0:2])[0]
        if sig != 0x6B76:
            return None

        name_len = struct.unpack("<H", raw[2:4])[0]
        data_length = struct.unpack("<I", raw[4:8])[0]
        data_offset_raw = struct.unpack("<I", raw[8:12])[0]
        value_type = struct.unpack("<I", raw[12:16])[0]
        flags = struct.unpack("<H", raw[16:18])[0]
        name_offset = offset + 4 + 20

        self.fh.seek(name_offset)
        name = (
            self.fh.read(name_len).decode("utf-16-le", errors="replace")
            if name_len > 0
            else "(Default)"
        )

        value = self._read_value_data(data_offset_raw, data_length, value_type)

        return {
            "name": name,
            "type": value_type,
            "type_name": VALUE_TYPES.get(value_type, f"UNKNOWN({value_type})"),
            "data_length": data_length,
            "value": value,
        }

    def _read_value_data(self, offset, length, value_type):
        """Baca data value berdasarkan tipe."""
        if length == 0:
            return None

        if length & 0x80000000:
            data = struct.pack("<I", offset)
            length = length & 0x7FFFFFFF
        else:
            self.fh.seek(offset + 0x1000)
            data = self.fh.read(length)

        if value_type == REG_SZ or value_type == REG_EXPAND_SZ:
            try:
                return data.decode("utf-16-le").rstrip("\x00")
            except Exception:
                return repr(data)
        elif value_type == REG_DWORD:
            if len(data) >= 4:
                return struct.unpack("<I", data[:4])[0]
            return None
        elif value_type == REG_QWORD:
            if len(data) >= 8:
                return struct.unpack("<Q", data[:8])[0]
            return None
        elif value_type == REG_MULTI_SZ:
            try:
                parts = data.decode("utf-16-le").split("\x00")
                return [p for p in parts if p]
            except Exception:
                return repr(data)
        elif value_type == REG_BINARY:
            return data.hex()
        else:
            if len(data) <= 64:
                return repr(data)
            return f"<binary {len(data)} bytes>"

    def _parse_lf(self, offset):
        """Parse LF/LH subkey list."""
        if offset == 0xFFFFFFFF or offset is None:
            return []

        self.fh.seek(offset)
        raw = self.fh.read(4)
        if len(raw) < 4:
            return []

        sig = raw[:2]
        count = struct.unpack("<H", raw[2:4])[0]
        subkey_offsets = []

        if sig in (b"lf", b"lh"):
            for i in range(count):
                self.fh.seek(offset + 4 + i * 8)
                entry = self.fh.read(8)
                nk_offset = struct.unpack("<i", entry[0:4])[0] + 0x1000
                subkey_offsets.append(nk_offset)
        elif sig in (b"ri", b"li"):
            for i in range(count):
                self.fh.seek(offset + 4 + i * 4)
                sub_offset = struct.unpack("<i", self.fh.read(4))[0] + 0x1000
                subkey_offsets.extend(self._parse_lf(sub_offset))

        return subkey_offsets

    def _parse_value_list(self, offset, num_values):
        """Parse daftar value (VK offsets)."""
        if offset == 0xFFFFFFFF or offset is None or num_values == 0:
            return []

        self.fh.seek(offset)
        values = []
        for i in range(num_values):
            self.fh.seek(offset + 4 + i * 4)
            vk_offset = struct.unpack("<i", self.fh.read(4))[0]
            if vk_offset != -1:
                vk = self._parse_vk(vk_offset + 0x1000)
                if vk:
                    values.append(vk)
        return values

    def traverse(self, path=None):
        """Traverse registry tree dan kembalikan struktur."""
        result = {"keys": [], "values": []}

        nk = self._parse_nk(self._root_offset)
        if not nk:
            return result

        current_path = []
        current_nk = nk

        if path:
            parts = [p for p in path.replace("/", "\\").split("\\") if p]
            for part in parts:
                found = False
                sub_offsets = self._parse_lf(current_nk["subkeys_list_offset"])
                for sub_off in sub_offsets:
                    sub_nk = self._parse_nk(sub_off)
                    if sub_nk and sub_nk["name"].lower() == part.lower():
                        current_path.append(sub_nk["name"])
                        current_nk = sub_nk
                        found = True
                        break
                if not found:
                    missing_path = "\\".join(parts)
                    print(f"[!] Key tidak ditemukan: {missing_path}")
                    return result

        self._collect_tree(current_nk, result)

        if current_path:
            display_path = "\\".join(current_path)
            print(f"[*] Path: {display_path}")
        return result

    def _collect_tree(self, nk, result):
        """Kumpulkan subkeys dan values secara rekursif."""
        sub_offsets = self._parse_lf(nk["subkeys_list_offset"])
        values = self._parse_value_list(nk["values_list_offset"], nk["num_values"])

        key_info = {
            "name": nk["name"],
            "timestamp": nk["timestamp"],
            "subkey_count": nk["num_subkeys"],
        }
        result["keys"].append(key_info)

        result["values"].extend(values)

        for sub_off in sub_offsets:
            sub_nk = self._parse_nk(sub_off)
            if sub_nk:
                self._collect_tree(sub_nk, result)

    def dump_all(self):
        """Dump seluruh isi hive."""
        return self.traverse()

    def get_value(self, path, value_name):
        """Dapatkan value spesifik dari path key."""
        result = self.traverse(path)
        for v in result.get("values", []):
            if v["name"].lower() == value_name.lower():
                return v
        return None

    def dump_json(self, output_path):
        """Export hasil ke JSON."""
        data = self.dump_all()
        serializable = {
            "hive_file": self.filepath,
            "hive_type": self.hive_type,
            "hive_name": self._hive_name,
            "timestamp": str(self._timestamp),
            "keys": [
                {
                    "name": k["name"],
                    "timestamp": str(k["timestamp"]),
                    "subkey_count": k["subkey_count"],
                }
                for k in data["keys"]
            ],
            "values": [
                {"name": v["name"], "type": v["type_name"], "value": v["value"]}
                for v in data["values"]
            ],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False, default=str)
        print(f"[+] Hasil disimpan ke: {output_path}")
        print(f"[+] Total: {len(data['keys'])} keys, {len(data['values'])} values")

    def dump_csv(self, output_path):
        """Export hasil ke CSV."""
        import csv

        data = self.dump_all()
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Key", "Value Name", "Type", "Value", "Key Timestamp"])
            current_key = self._hive_name
            for k in data["keys"]:
                current_key = k["name"]
            for v in data["values"]:
                writer.writerow(
                    [current_key, v["name"], v["type_name"], v["value"], str(self._timestamp)]
                )
        print(f"[+] CSV disimpan ke: {output_path}")


def filetime_to_datetime(ft):
    """Konversi Windows FILETIME ke datetime."""
    if ft == 0:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + ft / 10000000
    except (OverflowError, OSError):
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def print_sam_users(hive):
    """Tampilkan informasi user dari SAM hive."""
    print("\n[*] Menganalisis SAM — Informasi User Account...")
    result = hive.traverse("SAM\\Domains\\Account\\Users\\Names")
    for v in result.get("values", []):
        print(f"    [*] User: {v['name']} = {v['value']}")


def print_startup_entries(result, source=""):
    """Tampilkan entri startup/autorun."""
    for v in result.get("values", []):
        print(f"    [{source}] {v['name']} ({v['type_name']}): {v['value']}")


def print_usb_history(result):
    """Tampilkan USB storage history dari MountPoints2."""
    print("\n[*] USB Storage History (MountPoints2):")
    for k in result.get("keys", []):
        if k["name"] != "MountPoints2":
            print(f"    [*] {k['timestamp']}  {k['name']}")


def print_network_list(hive):
    """Tampilkan network profiles dari SOFTWARE hive."""
    print("\n[*] Network List Profiles:")

    for nk_path, label in NETWORK_KEYS.get("SOFTWARE", []):
        result = hive.traverse(nk_path)
        if result["values"]:
            print(f"\n[*] {label}:")
            last_key = ""
            for v in result["values"]:
                if v["name"] == "ProfileName":
                    print(f"    [+] SSID: {v['value']}")
                elif v["name"] == "Description":
                    print(f"        Deskripsi: {v['value']}")
                elif v["name"] == "FirstNetwork":
                    print(f"        First Network: {v['value']}")
                elif v["name"] == "DefaultGatewayMac":
                    print(f"        Gateway MAC: {v['value']}")


def print_typed_paths(result):
    """Tampilkan TypedPaths (URL history)."""
    print("\n[*] TypedPaths (Explorer URL History):")
    for v in result.get("values", []):
        print(f"    [*] {v['name']}: {v['value']}")


def print_recent_docs(result):
    """Tampilkan RecentDocs."""
    print("\n[*] RecentDocs:")
    for v in result.get("values", []):
        val = v["value"]
        if isinstance(val, str) and len(val) > 80:
            val = val[:80] + "..."
        print(f"    [*] {v['name']}: {val}")


def main():
    parser = argparse.ArgumentParser(
        description="Registry Reader Tool — Pembaca Forensik Windows Registry Hive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s --hive SAM --all
  %(prog)s --hive SOFTWARE --key "Microsoft\\Windows\\CurrentVersion\\Run"
  %(prog)s --hive NTUSER.DAT --all --output report.json
  %(prog)s --hive SYSTEM --key "ControlSet001\\Services"
  %(prog)s --hive SOFTWARE --all --output report.csv
        """,
    )
    parser.add_argument(
        "--hive",
        type=str,
        required=True,
        help="File hive registry (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, USRCLASS.DAT, SECURITY)",
    )
    parser.add_argument(
        "--key",
        type=str,
        default="",
        help="Path key spesifik (contoh: Microsoft\\Windows\\CurrentVersion\\Run)",
    )
    parser.add_argument("--all", action="store_true", help="Dump seluruh isi hive")
    parser.add_argument(
        "--output", type=str, default="", help="File output (JSON atau CSV, berdasarkan ekstensi)"
    )

    args = parser.parse_args()

    print(BANNER)
    print(f"[*] Waktu: {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"[*] File hive: {args.hive}")

    if not os.path.exists(args.hive):
        print(f"[!] File tidak ditemukan: {args.hive}")
        sys.exit(1)

    hive_type = guess_hive_type(args.hive)
    print(f"[*] Tipe hive terdeteksi: {hive_type}")

    hive = RegHive(args.hive)

    try:
        hive.open()

        if args.key:
            print(f"\n[*] Membaca key: {args.key}")
            result = hive.traverse(args.key)

            if result["values"]:
                print(f"\n[*] Values ({len(result['values'])}):")
                for v in result["values"]:
                    print(f"    [{v['type_name']:20s}] {v['name']:<30s} = {v['value']}")
            if result["keys"]:
                print(f"\n[*] Subkeys ({len(result['keys'])}):")
                for k in result["keys"][:50]:
                    print(f"    [*] {k['name']}  ({k['timestamp']})")
                if len(result["keys"]) > 50:
                    print(f"    ... dan {len(result['keys']) - 50} subkeys lainnya")
            if not result["values"] and not result["keys"]:
                print("[*] Key kosong (tidak ada values atau subkeys).")

        elif args.all:
            print(f"\n[*] Full dump hive: {hive_type}")

            if hive_type == "SAM":
                print_sam_users(hive)

            if hive_type == "SOFTWARE":
                for nk_path, label in KEY_INTEREST_PATHS.get("SOFTWARE", []):
                    try:
                        result = hive.traverse(nk_path)
                        if result["values"] or result["keys"]:
                            print(f"\n[*] {label}:")
                            if "Run" in nk_path:
                                print_startup_entries(result, label)
                            elif "TypedPaths" in nk_path:
                                print_typed_paths(result)
                            elif "RecentDocs" in nk_path:
                                print_recent_docs(result)
                            else:
                                for v in result["values"][:20]:
                                    print(f"    [{v['type_name']}] {v['name']} = {v['value']}")
                    except Exception as e:
                        pass

                print_network_list(hive)

            if hive_type == "NTUSER.DAT":
                for nk_path, label in KEY_INTEREST_PATHS.get("NTUSER.DAT", []):
                    try:
                        result = hive.traverse(nk_path)
                        if result["values"] or result["keys"]:
                            print(f"\n[*] {label}:")
                            if "Run" in nk_path:
                                print_startup_entries(result, label)
                            elif "TypedPaths" in nk_path:
                                print_typed_paths(result)
                            elif "RecentDocs" in nk_path:
                                print_recent_docs(result)
                            elif "MountPoints2" in nk_path:
                                print_usb_history(result)
                            elif "RunMRU" in nk_path:
                                print("[*] RunMRU (Command History):")
                                for v in result["values"]:
                                    print(f"    [*] {v['name']}: {v['value']}")
                            else:
                                for v in result["values"][:20]:
                                    print(f"    [{v['type_name']}] {v['name']} = {v['value']}")
                    except Exception as e:
                        pass

            if hive_type == "SYSTEM":
                for nk_path, label in KEY_INTEREST_PATHS.get("SYSTEM", []):
                    try:
                        result = hive.traverse(nk_path)
                        if result["values"] or result["keys"]:
                            print(f"\n[*] {label}:")
                            print(f"    Subkeys: {result['keys'][:30]}")
                            for v in result["values"][:20]:
                                print(f"    [{v['type_name']}] {v['name']} = {v['value']}")
                    except Exception:
                        pass

            if hive_type == "USRCLASS.DAT":
                for nk_path, label in KEY_INTEREST_PATHS.get("USRCLASS.DAT", []):
                    try:
                        result = hive.traverse(nk_path)
                        if result["values"] or result["keys"]:
                            print(f"\n[*] {label}:")
                            for v in result["values"][:30]:
                                print(f"    [*] {v['name']} = {v['value']}")
                    except Exception:
                        pass

            if hive_type not in ("SAM", "SYSTEM", "SOFTWARE", "NTUSER.DAT", "USRCLASS.DAT"):
                base_result = hive.dump_all()
                print(f"\n[*] Root keys ({len(base_result['keys'])}):")
                for k in base_result["keys"][:60]:
                    print(f"    [*] {k['name']}  ({k['timestamp']})  subkeys: {k['subkey_count']}")
                if len(base_result["keys"]) > 60:
                    print(f"    ... dan {len(base_result['keys']) - 60} keys lainnya")

        if args.output:
            ext = os.path.splitext(args.output)[1].lower()
            if ext == ".json":
                hive.dump_json(args.output)
            elif ext == ".csv":
                hive.dump_csv(args.output)
            else:
                print(f"[!] Format output tidak dikenal: {ext}. Gunakan .json atau .csv")

        print(f"\n[+] Selesai.")

    except ValueError as e:
        print(f"[!] Error parsing hive: {e}")
        print("[!] Pastikan file adalah registry hive Windows yang valid (regf signature).")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback

        traceback.print_exc()
    finally:
        hive.close()


if __name__ == "__main__":
    main()
