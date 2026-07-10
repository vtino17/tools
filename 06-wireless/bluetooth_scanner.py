#!/usr/bin/env python3
"""
Bluetooth LE Scanner
[ROOT untuk BLE low-level] Scanner Bluetooth klasik dan BLE dengan enumerasi
layanan SDP dan karakteristik GATT.

Penggunaan:
    python bluetooth_scanner.py --mode scan --timeout 10
    python bluetooth_scanner.py --mode services --target AA:BB:CC:DD:EE:FF
    python bluetooth_scanner.py --mode gatt --target AA:BB:CC:DD:EE:FF --output devices.json

Cross-platform: Linux (bluez), Windows (Windows.Devices.Bluetooth).
Berjalan optimal di Linux dengan bluez.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime


def check_linux_bluez():
    if os.name != "posix":
        return False
    try:
        subprocess.run(["which", "hcitool"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def scan_linux(args):
    print("[*] Menggunakan bluez (Linux)")
    timeout = args.timeout

    try:
        subprocess.run(["hciconfig", "hci0", "up"], capture_output=True)
    except Exception:
        pass

    print(f"[*] Memindai perangkat Bluetooth (timeout: {timeout}s)...")
    print(f"    {'MAC Address':<19} {'Nama':<30} {'RSSI':>5}  {'Tipe'}")
    print(f"    {'-'*19} {'-'*30} {'-'*6}  {'-'*15}")

    scan_cmd = ["hcitool", "scan", "--flush"]
    devices = {}

    proc = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    start_time = time.time()

    def flush_output():
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line and "Scanning" not in line:
                parts = line.split("\t", 1)
                if len(parts) >= 2:
                    mac, name = parts[0].strip(), parts[1].strip()
                    if mac not in devices:
                        devices[mac] = {"name": name, "mac": mac}
                        print(f"    {mac:<19} {name[:28]:<30} {'n/a':>5}  Classic")

    flush_output()

    while time.time() - start_time < timeout:
        if proc.poll() is not None:
            break
        flush_output()
        time.sleep(0.5)

    proc.terminate()
    flush_output()

    if args.include_ble:
        print(f"\n[*] Memindai perangkat BLE...")
        ble_scan = ["hcitool", "lescan", "--duplicates"]
        ble_proc = subprocess.Popen(
            ble_scan, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        ble_start = time.time()
        ble_devices = set()

        while time.time() - ble_start < min(timeout, 15):
            line = ble_proc.stdout.readline()
            if line:
                line = line.strip()
                if line and len(line) > 15:
                    mac = line[:17].strip()
                    name = line[17:].strip() if len(line) > 17 else ""
                    if mac not in ble_devices and mac not in devices:
                        ble_devices.add(mac)
                        print(f"    {mac:<19} {name[:28]:<30} {'n/a':>5}  BLE")
            else:
                break

        ble_proc.terminate()
        for mac in ble_devices:
            if mac not in devices:
                devices[mac] = {"name": "(BLE)", "mac": mac, "type": "BLE"}

    print(f"\n[+] Pemindaian selesai. {len(devices)} perangkat ditemukan.")
    return devices


def scan_services_linux(target: str):
    print(f"[*] Menghubungkan ke {target} untuk query SDP...")
    try:
        result = subprocess.run(
            ["sdptool", "browse", target], capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            print(f"[!] Gagal query SDP: {result.stderr.strip()}")
            return None
        services = []
        current_service = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Service Name:"):
                if current_service:
                    services.append(current_service)
                current_service = {"name": line.split(":", 1)[1].strip(), "channels": []}
            if line.startswith("Channel:") and current_service:
                current_service["channels"].append(line.split(":", 1)[1].strip())
            if "RFCOMM" in line and current_service:
                current_service["protocol"] = "RFCOMM"
            if "L2CAP" in line and current_service:
                current_service["protocol"] = "L2CAP"
        if current_service:
            services.append(current_service)

        if services:
            print(f"\n[+] {len(services)} layanan ditemukan pada {target}:")
            for svc in services:
                print(f"    - {svc['name']} ({svc.get('protocol', 'N/A')})")
                for ch in svc.get("channels", []):
                    print(f"      Channel: {ch}")
        else:
            print("[!] Tidak ada layanan SDP ditemukan.")
        return services
    except subprocess.TimeoutExpired:
        print("[!] Timeout saat query SDP.")
        return None
    except FileNotFoundError:
        print("[!] sdptool tidak ditemukan. Install bluez-utils.")
        return None


def scan_gatt_linux(target: str):
    print(f"[*] Menghubungkan ke {target} untuk enumerasi GATT...")
    try:
        result = subprocess.run(
            ["gatttool", "-b", target, "--primary"], capture_output=True, text=True, timeout=10
        )
        print(f"[*] Daftar service GATT:")
        services = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if "end grp handle" in line:
                parts = line.split()
                if len(parts) >= 6:
                    handle = parts[3]
                    uuid = parts[5]
                    services.append({"handle": handle, "uuid": uuid})
                    print(f"    Handle: {handle}, UUID: {uuid}")
        return services
    except subprocess.TimeoutExpired:
        print("[!] Timeout saat enumerasi GATT.")
        return None
    except FileNotFoundError:
        print("[!] gatttool tidak ditemukan. Install bluez-utils.")
        return None


def scan_windows_bt():
    print("[*] Menggunakan API Windows Bluetooth...")
    script = """
$ErrorActionPreference = 'SilentlyContinue'
[Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
Function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}
[Windows.Devices.Bluetooth.BluetoothDevice]::GetDevicesAsync() | ForEach-Object {
    $devices = Await $_ ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Bluetooth.BluetoothDevice]])
    foreach ($d in $devices) {
        Write-Output "$($d.BluetoothAddress.ToString('X12'))|$($d.Name)|$($d.DeviceInformation.Kind)"
    }
}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        devices = {}
        for line in result.stdout.strip().splitlines():
            parts = line.strip().split("|", 2)
            if len(parts) >= 2:
                mac_raw = parts[0]
                mac = ":".join(mac_raw[i : i + 2] for i in range(0, 12, 2)).upper()
                name = parts[1] if parts[1] else "(Unknown)"
                dev_type = parts[2] if len(parts) > 2 else "Unknown"
                devices[mac] = {"name": name, "mac": mac, "type": dev_type}
                print(f"    {mac:<19} {name[:28]:<30} {'n/a':>5}  {dev_type}")
        print(f"\n[+] {len(devices)} perangkat ditemukan.")
        return devices
    except Exception as e:
        print(f"[!] Gagal scan Windows: {e}")
        return {}


def export_json(devices: dict, services: list | None, output_path: str, target: str | None):
    data = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "devices": [],
        "services": services or [],
    }
    for mac, info in devices.items():
        data["devices"].append(
            {"mac": mac, "name": info.get("name", ""), "type": info.get("type", "")}
        )
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Hasil diekspor ke: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Bluetooth LE Scanner - Scan perangkat, layanan SDP, dan karakteristik GATT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python bluetooth_scanner.py --mode scan --timeout 15
  python bluetooth_scanner.py --mode services --target AA:BB:CC:DD:EE:FF
  python bluetooth_scanner.py --mode gatt --target AA:BB:CC:DD:EE:FF --output hasil.json
        """,
    )
    parser.add_argument(
        "--mode",
        default="scan",
        choices=["scan", "services", "gatt"],
        help="Mode operasi: scan, services, atau gatt (default: scan)",
    )
    parser.add_argument("--target", help="MAC address target untuk mode services/gatt")
    parser.add_argument(
        "--timeout", type=int, default=10, help="Durasi scan dalam detik (default: 10)"
    )
    parser.add_argument("--output", help="File output JSON")
    parser.add_argument("--include-ble", action="store_true", help="Sertakan scan BLE (Linux)")
    args = parser.parse_args()

    if args.mode in ("services", "gatt") and not args.target:
        sys.exit("[!] --target diperlukan untuk mode services/gatt")

    print("=" * 55)
    print("  Bluetooth LE Scanner")
    print("=" * 55)

    is_linux = check_linux_bluez()
    devices = {}
    services = None

    if is_linux:
        if args.mode == "scan":
            devices = scan_linux(args)
        elif args.mode == "services":
            devices = {}
            services = scan_services_linux(args.target)
        elif args.mode == "gatt":
            devices = {}
            services = scan_gatt_linux(args.target)
    else:
        if os.name == "nt":
            if args.mode == "scan":
                devices = scan_windows_bt()
            else:
                print("[!] Mode services/gatt hanya tersedia di Linux dengan bluez.")
                return
        else:
            print("[!] Platform tidak didukung. Gunakan Linux dengan bluez.")
            print("    Install: sudo apt install bluez bluez-utils")
            return

    if args.output:
        export_json(devices, services, args.output, args.target)


if __name__ == "__main__":
    main()
