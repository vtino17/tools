#!/usr/bin/env python3
"""
MAC Address Changer
Mengubah MAC address network interface untuk anonymity.
Usage:
  python mac_changer.py -i eth0 -m random
  python mac_changer.py -i eth0 -m 00:11:22:33:44:55
"""
import argparse
import sys
import re
import os
import random
import subprocess


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        print("[!] MAC changing requires root privileges on Linux")
        return False
    if os.name == "nt":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("[!] MAC changing requires Administrator on Windows")
                return False
        except:
            pass
    return True


def generate_random_mac():
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] = (mac[0] & 0xfe) | 0x02
    parts = []
    for b in mac:
        parts.append("{:02x}".format(b))
    return ":".join(parts)


def generate_vendor_mac(vendor_prefix):
    if not re.match(r"^([0-9a-fA-F]{2}[:]){2}[0-9a-fA-F]{2}$", vendor_prefix):
        print("[!] Vendor prefix harus format XX:XX:XX")
        return None
    suffix = [random.randint(0x00, 0xff) for _ in range(3)]
    parts = []
    for b in suffix:
        parts.append("{:02x}".format(b))
    return vendor_prefix + ":" + ":".join(parts)


def get_current_mac_linux(interface):
    try:
        result = subprocess.run(["ip", "link", "show", interface],
                                capture_output=True, text=True)
        match = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout)
        if match:
            return match.group(1)
    except:
        pass
    return None


def change_mac_linux(interface, new_mac):
    try:
        subprocess.run(["ip", "link", "set", "dev", interface, "down"],
                       check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", "dev", interface, "address", new_mac],
                       check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", "dev", interface, "up"],
                       check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print("[!] Error: " + str(e))
        return False


def change_mac_windows(interface, new_mac):
    try:
        import winreg
        adapters = get_windows_adapters()
        target_guid = None
        for name, guid in adapters.items():
            if interface.lower() in name.lower():
                target_guid = guid
                break

        if not target_guid:
            print("[!] Interface tidak ditemukan: " + interface)
            return False

        ndis_guid = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
        reg_path = r"SYSTEM\CurrentControlSet\Control\Class" + chr(92) + ndis_guid
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS) as reg:
            for i in range(100):
                try:
                    subkey_name = winreg.EnumKey(reg, i)
                    with winreg.OpenKey(reg, subkey_name, 0, winreg.KEY_ALL_ACCESS) as subkey:
                        try:
                            current_guid, _ = winreg.QueryValueEx(subkey, "NetCfgInstanceId")
                            if current_guid == target_guid:
                                winreg.SetValueEx(subkey, "NetworkAddress", 0, winreg.REG_SZ, new_mac.replace(":", ""))
                                return True
                        except FileNotFoundError:
                            continue
                except OSError:
                    break
    except Exception as e:
        print("[!] Error: " + str(e))
    return False


def get_windows_adapters():
    try:
        import winreg
        adapters = {}
        ndis_guid = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
        reg_path = r"SYSTEM\CurrentControlSet\Control\Network" + chr(92) + ndis_guid
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ) as reg:
            for i in range(100):
                try:
                    subkey_name = winreg.EnumKey(reg, i)
                    with winreg.OpenKey(reg, subkey_name, 0, winreg.KEY_READ) as subkey:
                        try:
                            name, _ = winreg.QueryValueEx(subkey, "Connection")
                            guid_val, _ = winreg.QueryValueEx(subkey, "NetCfgInstanceId")
                            adapters[name] = guid_val
                        except FileNotFoundError:
                            continue
                except OSError:
                    break
        return adapters
    except:
        return {}


def restore_mac_linux(interface):
    try:
        subprocess.run(["ip", "link", "set", "dev", interface, "down"],
                       check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", "dev", interface, "up"],
                       check=True, capture_output=True)
        return True
    except:
        return False


def main():
    parser = argparse.ArgumentParser(description="MAC Address Changer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("-m", "--mac", help="New MAC address (use 'random' for random, 'XX:XX:XX' for vendor OUI)")
    parser.add_argument("-r", "--reset", action="store_true", help="Reset to permanent MAC")
    parser.add_argument("-s", "--show", action="store_true", help="Show current MAC")
    parser.add_argument("-l", "--list", action="store_true", help="List interfaces (Windows)")
    args = parser.parse_args()

    if not check_root():
        sys.exit(1)

    if args.list and os.name == "nt":
        adapters = get_windows_adapters()
        print("[*] Available Windows adapters:")
        for name, guid in adapters.items():
            print("    " + name + " (GUID: " + guid + ")")
        return

    if args.show:
        if os.name == "posix":
            mac = get_current_mac_linux(args.interface)
            if mac:
                print("[*] Current MAC for " + args.interface + ": " + mac)
            else:
                print("[!] Cannot read MAC for " + args.interface)
        return

    if args.reset:
        print("[*] Resetting MAC for " + args.interface)
        if os.name == "posix":
            if restore_mac_linux(args.interface):
                print("[+] MAC reset (will revert to permanent on reconnect)")
        return

    if not args.mac:
        print("[!] Butuh -m/--mac atau -r/--reset")
        sys.exit(1)

    if args.mac.lower() == "random":
        new_mac = generate_random_mac()
    elif re.match(r"^([0-9a-fA-F]{2}[:]){2}[0-9a-fA-F]{2}$", args.mac):
        new_mac = generate_vendor_mac(args.mac)
        if not new_mac:
            sys.exit(1)
    elif re.match(r"^([0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2}$", args.mac):
        new_mac = args.mac
    else:
        print("[!] Format MAC tidak valid. Gunakan XX:XX:XX:XX:XX:XX atau 'random'")
        sys.exit(1)

    print("[*] Target interface: " + args.interface)
    print("[*] New MAC: " + new_mac)

    if os.name == "posix":
        current = get_current_mac_linux(args.interface)
        if current:
            print("[*] Current MAC: " + current)
        if change_mac_linux(args.interface, new_mac):
            print("[+] MAC changed successfully")
            new_mac_actual = get_current_mac_linux(args.interface)
            if new_mac_actual:
                print("[+] Verified new MAC: " + new_mac_actual)
    else:
        if change_mac_windows(args.interface, new_mac):
            print("[+] MAC changed in registry. Disable/Re-enable adapter to apply.")


if __name__ == "__main__":
    main()

