#!/usr/bin/env python3
"""
SNMP Enumerator Tool.

Melakukan enumerasi perangkat via SNMP v1/v2c menggunakan community string.
Mencoba community string umum (public, private, dll) dan mengekstrak informasi
sistem, interface jaringan, routing table, proses, software, port, dan ARP table.

Menggunakan pysnmp jika tersedia, dengan fallback raw UDP socket.

Usage:
    python snmp_scanner.py --target 192.168.1.1
    python snmp_scanner.py --target 192.168.1.1 --port 161
    python snmp_scanner.py --target 192.168.1.0/24 --wordlist communities.txt
"""

import argparse
import ipaddress
import socket
import struct
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd, nextCmd, bulkCmd,
    )
    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False

DEFAULT_COMMUNITIES = [
    "public", "private", "read", "write", "admin",
    "snmp", "manager", "monitor", "cisco", "ilmi",
    "security", "default", "secret", "password", "root",
    "system", "snmpd", "tivoli", "openview", "orig_equip_mfg",
]

OID_CATEGORIES = {
    "Informasi Sistem": [
        ("1.3.6.1.2.1.1.1.0", "sysDescr"),
        ("1.3.6.1.2.1.1.2.0", "sysObjectID"),
        ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
        ("1.3.6.1.2.1.1.4.0", "sysContact"),
        ("1.3.6.1.2.1.1.5.0", "sysName"),
        ("1.3.6.1.2.1.1.6.0", "sysLocation"),
        ("1.3.6.1.2.1.1.7.0", "sysServices"),
    ],
    "Interface Jaringan": [
        ("1.3.6.1.2.1.2.2.1.1", "ifIndex"),
        ("1.3.6.1.2.1.2.2.1.2", "ifDescr"),
        ("1.3.6.1.2.1.2.2.1.3", "ifType"),
        ("1.3.6.1.2.1.2.2.1.5", "ifSpeed"),
        ("1.3.6.1.2.1.2.2.1.6", "ifPhysAddress"),
        ("1.3.6.1.2.1.2.2.1.8", "ifOperStatus"),
        ("1.3.6.1.2.1.4.20.1.1", "ipAdEntAddr"),
        ("1.3.6.1.2.1.4.20.1.2", "ipAdEntIfIndex"),
        ("1.3.6.1.2.1.4.20.1.3", "ipAdEntNetMask"),
        ("1.3.6.1.2.1.4.22.1.2", "ipNetToMediaPhysAddress"),
    ],
    "Routing Table": [
        ("1.3.6.1.2.1.4.21.1.1", "ipRouteDest"),
        ("1.3.6.1.2.1.4.21.1.2", "ipRouteIfIndex"),
        ("1.3.6.1.2.1.4.21.1.7", "ipRouteNextHop"),
        ("1.3.6.1.2.1.4.21.1.8", "ipRouteType"),
        ("1.3.6.1.2.1.4.21.1.11", "ipRouteMask"),
    ],
    "Proses Berjalan": [
        ("1.3.6.1.2.1.25.4.2.1.1", "hrSWRunIndex"),
        ("1.3.6.1.2.1.25.4.2.1.2", "hrSWRunName"),
        ("1.3.6.1.2.1.25.4.2.1.4", "hrSWRunPath"),
        ("1.3.6.1.2.1.25.4.2.1.5", "hrSWRunParameters"),
        ("1.3.6.1.2.1.25.4.2.1.6", "hrSWRunType"),
        ("1.3.6.1.2.1.25.4.2.1.7", "hrSWRunStatus"),
    ],
    "Software Terinstal": [
        ("1.3.6.1.2.1.25.6.3.1.1", "hrSWInstalledIndex"),
        ("1.3.6.1.2.1.25.6.3.1.2", "hrSWInstalledName"),
        ("1.3.6.1.2.1.25.6.3.1.4", "hrSWInstalledType"),
    ],
    "Port Mendengarkan": [
        ("1.3.6.1.2.1.6.13.1.1", "tcpConnLocalAddress"),
        ("1.3.6.1.2.1.6.13.1.2", "tcpConnLocalPort"),
        ("1.3.6.1.2.1.6.13.1.3", "tcpConnRemAddress"),
        ("1.3.6.1.2.1.6.13.1.4", "tcpConnRemPort"),
        ("1.3.6.1.2.1.6.13.1.5", "tcpConnState"),
        ("1.3.6.1.2.1.7.5.1.1", "udpLocalAddress"),
        ("1.3.6.1.2.1.7.5.1.2", "udpLocalPort"),
    ],
    "ARP Table": [
        ("1.3.6.1.2.1.4.22.1.1", "ipNetToMediaIfIndex"),
        ("1.3.6.1.2.1.4.22.1.2", "ipNetToMediaPhysAddress"),
        ("1.3.6.1.2.1.4.22.1.3", "ipNetToMediaNetAddress"),
        ("1.3.6.1.2.1.4.22.1.4", "ipNetToMediaType"),
    ],
}


def log_info(msg: str) -> None:
    print(f"[*] {msg}")


def log_success(msg: str) -> None:
    print(f"[+] {msg}")


def log_error(msg: str) -> None:
    print(f"[!] {msg}")


def log_warn(msg: str) -> None:
    print(f"[-] {msg}")


def snmp_get_pysnmp(target: str, port: int, community: str, oid: str) -> str | None:
    """SNMPv1/SNMPv2c SNMP GET menggunakan pysnmp."""
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((target, port), timeout=3, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication or error_status:
            return None
        for vb in var_binds:
            return vb[1].prettyPrint()
    except Exception:
        return None
    return None


def snmp_walk_pysnmp(target: str, port: int, community: str, oid: str) -> list[tuple[str, str]]:
    """SNMP WALK menggunakan pysnmp bulkCmd."""
    results = []
    try:
        for (error_indication, error_status, error_index, var_binds) in bulkCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((target, port), timeout=3, retries=1),
            ContextData(),
            0, 25,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if error_indication:
                break
            if error_status:
                break
            for vb in var_binds:
                oid_str = str(vb[0])
                val_str = vb[1].prettyPrint()
                results.append((oid_str, val_str))
            if len(var_binds) == 0:
                break
    except Exception:
        pass
    return results


def snmp_test_raw(target: str, port: int, communities: list[str]) -> list[str]:
    """Uji community string via raw UDP SNMP GET request."""
    valid = []

    for community in communities:
        try:
            pdu = _encode_snmp_get(community, "1.3.6.1.2.1.1.1.0")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(pdu, (target, port))
            data, _ = sock.recvfrom(2048)
            sock.close()

            if data and len(data) > 2:
                valid.append(community)
        except socket.timeout:
            pass
        except Exception:
            pass

    return valid


def _encode_snmp_get(community: str, oid: str) -> bytes:
    """Encode SNMP GET request secara manual (BER encoding dasar)."""
    oid_parts = [int(x) for x in oid.split(".")]
    encoded_oid = bytes([oid_parts[0] * 40 + oid_parts[1]])
    for part in oid_parts[2:]:
        encoded_oid += _encode_ber_integer(part)

    oid_tlv = b"\x06" + _encode_ber_length(len(encoded_oid)) + encoded_oid
    null_tlv = b"\x05\x00"
    varbind = b"\x30" + _encode_ber_length(len(oid_tlv + null_tlv)) + oid_tlv + null_tlv
    varbinds = b"\x30" + _encode_ber_length(len(varbind)) + varbind

    community_bytes = community.encode("ascii")
    community_tlv = b"\x04" + _encode_ber_length(len(community_bytes)) + community_bytes

    request_id = b"\x02\x01\x00"
    error = b"\x02\x01\x00"
    error_index = b"\x02\x01\x00"

    pdu_data = request_id + error + error_index + varbinds
    pdu = b"\xa0" + _encode_ber_length(len(pdu_data)) + pdu_data

    version = b"\x02\x01\x00"
    msg = version + community_tlv + pdu
    msg = b"\x30" + _encode_ber_length(len(msg)) + msg
    return msg


def _encode_ber_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    needed = 0
    n = length
    while n:
        needed += 1
        n >>= 8
    result = bytes([0x80 | needed])
    for i in range(needed - 1, -1, -1):
        result += bytes([(length >> (i * 8)) & 0xFF])
    return result


def _encode_ber_integer(val: int) -> bytes:
    if val == 0:
        return b"\x00"
    result = b""
    n = val
    while n:
        result = bytes([n & 0xFF]) + result
        n >>= 8
    if result[0] & 0x80:
        result = b"\x00" + result
    return b"\x02" + _encode_ber_length(len(result)) + result


def test_community(target: str, port: int, community: str) -> tuple[str, bool]:
    """Uji satu community string, return (community, is_valid)."""
    if HAS_PYSNMP:
        result = snmp_get_pysnmp(target, port, community, "1.3.6.1.2.1.1.1.0")
        return (community, result is not None)

    try:
        pdu = _encode_snmp_get(community, "1.3.6.1.2.1.1.1.0")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(pdu, (target, port))
        data, _ = sock.recvfrom(2048)
        sock.close()
        return (community, len(data) > 2 and data[0] == 0x30)
    except socket.timeout:
        return (community, False)
    except Exception:
        return (community, False)


def enumerate_with_community(target: str, port: int, community: str) -> dict[str, dict[str, str]]:
    """Enumerasi penuh dengan community string yang valid."""
    results: dict[str, dict[str, str]] = {}

    for category, oids in OID_CATEGORIES.items():
        category_data: dict[str, str] = {}
        log_info(f"  Mengambil {category}...")

        for oid, label in oids:
            if "_" in oid:
                walked = snmp_walk_pysnmp(target, port, community, oid) if HAS_PYSNMP else []
                if walked:
                    for oid_str, val_str in walked:
                        category_data[f"{label}[{oid_str}]"] = val_str
            elif HAS_PYSNMP:
                val = snmp_get_pysnmp(target, port, community, oid)
                if val:
                    category_data[label] = val

        if category_data:
            results[category] = category_data
            log_success(f"  {category}: {len(category_data)} item")
        else:
            log_warn(f"  {category}: (tidak tersedia)")

    return results


def scan_single_host(target: str, port: int, communities: list[str]) -> dict:
    """Pindai satu host SNMP."""
    result = {"target": target, "valid_communities": [], "data": {}}

    udp_ok = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b"\x00", (target, port))
        s.close()
        udp_ok = True
    except Exception:
        pass

    if not udp_ok:
        log_error(f"Port {port}/UDP tidak responsif pada {target}")
        return result

    log_info(f"Menguji {len(communities)} community string pada {target}...")

    valid = []
    for comm in communities:
        status = test_community(target, port, comm)
        if status[1]:
            valid.append(comm)
            log_success(f"Community valid: '{comm}'")

    result["valid_communities"] = valid

    if valid:
        best = "private" if "private" in valid else valid[0]
        log_info(f"Menggunakan community '{best}' untuk enumerasi...")
        result["data"] = enumerate_with_community(target, port, best)

    return result


def expand_targets(target: str) -> list[str]:
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            return [str(h) for h in net.hosts()]
    except ValueError:
        pass
    return [target]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SNMP Enumerator Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s --target 192.168.1.1
  %(prog)s --target 192.168.1.0/24
  %(prog)s --target 192.168.1.1 --wordlist communities.txt
  %(prog)s --target 192.168.1.1 --port 1161
        """,
    )
    parser.add_argument("--target", "-t", required=True, help="Target IP, hostname, atau subnet")
    parser.add_argument("--port", "-p", type=int, default=161, help="Port SNMP (default: 161)")
    parser.add_argument("--wordlist", "-w", help="File wordlist community string")
    parser.add_argument("--threads", type=int, default=10, help="Thread paralel (default: 10)")
    args = parser.parse_args()

    if not HAS_PYSNMP:
        log_warn("pysnmp tidak terinstall. Menggunakan raw UDP socket (kemampuan terbatas).")
        log_info("Install pysnmp: pip install pysnmp")

    communities = DEFAULT_COMMUNITIES.copy()
    if args.wordlist:
        try:
            with open(args.wordlist, encoding="utf-8") as f:
                custom = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            communities = custom
            log_info(f"Loaded {len(communities)} community string dari {args.wordlist}")
        except FileNotFoundError:
            log_error(f"File wordlist tidak ditemukan: {args.wordlist}")
            sys.exit(1)

    targets = expand_targets(args.target)
    results = []

    if len(targets) == 1:
        results.append(scan_single_host(targets[0], args.port, communities))
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_single_host, t, args.port, communities): t for t in targets}
            for future in as_completed(futures):
                results.append(future.result())

    print(f"\n{'=' * 60}")
    print(f"  HASIL ENUMERASI SNMP")
    print(f"{'=' * 60}")

    for r in results:
        if not r["valid_communities"]:
            log_warn(f"{r['target']}: Tidak ada community string valid")
            continue

        print(f"\n  [TARGET] {r['target']}")
        print(f"  Community valid: {', '.join(r['valid_communities'])}")

        if not r["data"]:
            print("  (tidak ada data berhasil diekstrak)")
            continue

        for category, items in r["data"].items():
            print(f"\n  --- {category} ---")
            for key, value in items.items():
                print(f"    {key:30s} : {value}")


if __name__ == "__main__":
    main()
