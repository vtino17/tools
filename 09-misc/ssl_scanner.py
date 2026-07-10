#!/usr/bin/env python3
"""
SSL/TLS Scanner - Check SSL configuration
Menganalisa sertifikat SSL dan konfigurasi TLS.
Usage: python ssl_scanner.py -t target.com -p 443
"""
import argparse
import sys
import socket
import ssl
import re
from datetime import datetime


def get_certificate(host, port, timeout=10):
    """Get SSL certificate"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def parse_certificate(cert):
    """Parse certificate info"""
    if not cert:
        return None

    info = {
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "version": cert.get("version"),
        "serial": cert.get("serialNumber"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [],
        "signature_algorithm": cert.get("subjectAltName", []),
    }

    # Parse subject alt names
    san = cert.get("subjectAltName", [])
    for san_type, san_value in san:
        info["subject_alt_names"].append(f"{san_type}:{san_value}")

    return info


def check_expiry(not_after):
    """Check certificate expiry"""
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        delta = expiry - datetime.now()
        return {
            "expiry": expiry,
            "days_remaining": delta.days,
            "expired": delta.days < 0,
        }
    except:
        return None


def check_protocols(host, port, timeout=5):
    """Check supported SSL/TLS protocols"""
    protocols = {
        "SSLv2": ssl.PROTOCOL_SSLv23,
        "SSLv3": ssl.PROTOCOL_SSLv23,
        "TLSv1.0": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
    }

    results = {}
    for name in ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
        try:
            if name == "TLSv1.3" and hasattr(ssl, "PROTOCOL_TLSv1_3"):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            elif name == "TLSv1.0":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1
            elif name == "TLSv1.1":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1_1
                context.maximum_version = ssl.TLSVersion.TLSv1_1
            elif name == "TLSv1.2":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            else:
                continue

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    results[name] = ssock.version()
        except (ssl.SSLError, OSError, AttributeError) as e:
            results[name] = f"Not supported ({type(e).__name__})"
    return results


def check_ciphers(host, port, timeout=5):
    """Check supported cipher suites"""
    weak = ["RC4", "MD5", "DES", "3DES", "NULL", "EXPORT", "anon"]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    name, proto, bits = cipher
                    is_weak = any(w in name for w in weak)
                    return {
                        "cipher": name,
                        "protocol": proto,
                        "bits": bits,
                        "weak": is_weak,
                    }
    except Exception as e:
        return {"error": str(e)}
    return None


def main():
    parser = argparse.ArgumentParser(description="SSL/TLS Configuration Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target hostname")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port (default 443)")
    args = parser.parse_args()

    print(f"[*] Target: {args.target}:{args.port}")
    print("=" * 60)

    # Get certificate
    cert = get_certificate(args.target, args.port)
    if not cert:
        sys.exit(1)

    info = parse_certificate(cert)
    if not info:
        print("[!] Gagal parse certificate")
        sys.exit(1)

    print("\n[1] CERTIFICATE INFO")
    print("-" * 60)
    print(f"  Subject: {info['subject']}")
    print(f"  Issuer: {info['issuer']}")
    print(f"  Version: {info['version']}")
    print(f"  Serial: {info['serial']}")

    # Expiry
    expiry = check_expiry(info['not_after'])
    if expiry:
        print(f"  Not Before: {info['not_before']}")
        print(f"  Not After: {info['not_after']}")
        print(f"  Days Remaining: {expiry['days_remaining']}")
        if expiry['expired']:
            print(f"  [!] EXPIRED")
        elif expiry['days_remaining'] < 30:
            print(f"  [!] EXPIRES SOON")

    if info['subject_alt_names']:
        print(f"  Subject Alt Names:")
        for san in info['subject_alt_names']:
            print(f"    - {san}")

    # Check protocols
    print("\n[2] PROTOCOL SUPPORT")
    print("-" * 60)
    protocols = check_protocols(args.target, args.port)
    for name, result in protocols.items():
        status = "[!]" if "Not" in str(result) else "[+]"
        if "TLSv1.0" in name or "TLSv1.1" in name:
            status = "[!]" if "TLS" in str(result) and "Not" not in str(result) else "[+]"
            print(f"  {status} {name}: {result} {'(DEPRECATED)' if 'TLS' in str(result) and 'Not' not in str(result) else ''}")
        else:
            print(f"  {status} {name}: {result}")

    # Check ciphers
    print("\n[3] CIPHER")
    print("-" * 60)
    cipher = check_ciphers(args.target, args.port)
    if cipher and "error" not in cipher:
        status = "[!]" if cipher.get("weak") else "[+]"
        print(f"  {status} Current cipher: {cipher['cipher']}")
        print(f"      Protocol: {cipher['protocol']}")
        print(f"      Bits: {cipher['bits']}")
        if cipher.get("weak"):
            print(f"      [!] WEAK CIPHER DETECTED")

    print("\n" + "=" * 60)
    print("[*] SSL scan complete")


if __name__ == "__main__":
    main()

