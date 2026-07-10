#!/usr/bin/env python3
"""
Docker Enumeration & Security Checker.

Checks Docker daemon API exposure, enumerates containers/images/volumes/networks,
and detects misconfigurations for container escape.

Usage:
    # Check local Docker socket
    python docker_enum.py

    # Check remote Docker API
    python docker_enum.py --host 192.168.1.100 --port 2375

    # Check remote with TLS
    python docker_enum.py --host docker.example.com --port 2376 --tls

    # Deep security analysis
    python docker_enum.py --deep
"""

import argparse
import http.client
import json
import os
import socket as sock
import ssl
import sys
from http.client import HTTPConnection
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("[!] Modul 'requests' tidak ditemukan. Install: pip install requests")
    sys.exit(1)

DOCKER_SOCK = "/var/run/docker.sock"
COMMON_DOCKER_PORTS = [2375, 2376, 4243, 5555]


def unix_sock_request(path, method="GET", body=None):
    """Make HTTP request over Unix socket."""
    try:
        import urllib3
        from urllib3.connection import HTTPConnection as U3HTTPConnection
        from urllib3.util import Timeout

        class DockerUnixConnection(U3HTTPConnection):
            def connect(self):
                self.sock = sock.sock(sock.AF_UNIX, sock.SOCK_STREAM)
                self.sock.connect(self._kwargs["socket_path"])

    except ImportError:
        pass

    try:
        conn = http.client.HTTPConnection("localhost")
        conn.sock = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
        conn.sock.connect(DOCKER_SOCK)
        if sys.version_info >= (3, 12):
            conn.putrequest(method, f"http://localhost/v1.43{path}")
        else:
            conn._http_vsn = 11
            conn._http_vsn_str = "HTTP/1.1"
            conn.putrequest(method, f"/v1.43{path}")
        conn.putheader("Host", "localhost")
        if body:
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders()
            conn.send(body.encode())
        else:
            conn.endheaders()
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        if resp.status in (200, 201):
            return json.loads(data)
        else:
            print(f"  [!] HTTP {resp.status}: {data[:200]}")
    except Exception as e:
        print(f"  [!] Gagal koneksi ke Docker socket: {e}")
    return None


def check_docker_api(base_url, verify_tls=True):
    """Check if Docker API is accessible."""
    if base_url.startswith("unix://"):
        sock_path = base_url.replace("unix://", "")
        if os.path.exists(sock_path):
            print(f"[+] Docker socket ditemukan: {sock_path}")
            info = unix_sock_request("/info")
            if info:
                print(f"[+] API dapat diakses tanpa autentikasi!")
                return {"url": base_url, "accessible": True, "auth": "none", "info": info}
            else:
                print(f"[!] Socket ada tapi API tidak dapat diakses")
                return {"url": base_url, "accessible": False}
        else:
            print(f"[-] Docker socket tidak ditemukan: {sock_path}")
            return {"url": base_url, "accessible": False}

    try:
        resp = requests.get(f"{base_url}/v1.43/info", timeout=5, verify=verify_tls)
        if resp.status_code == 200:
            info = resp.json()
            print(f"[+] Docker API ditemukan di: {base_url}")
            print(f"[+] API dapat diakses tanpa autentikasi!")
            return {"url": base_url, "accessible": True, "auth": "none", "info": info}
        elif resp.status_code == 401:
            print(f"[*] Docker API di {base_url} memerlukan autentikasi")
            return {"url": base_url, "accessible": True, "auth": "required"}
        else:
            print(f"[-] Docker API tidak dapat diakses (HTTP {resp.status_code})")
    except requests.exceptions.SSLError:
        print(f"[*] TLS error, mencoba tanpa verifikasi...")
        try:
            resp = requests.get(f"{base_url}/v1.43/info", timeout=5, verify=False)
            if resp.status_code == 200:
                print(f"[+] Docker API ditemukan (TLS self-signed)")
                return {"url": base_url, "accessible": True, "auth": "none"}
        except Exception:
            pass
        print(f"[-] Docker API tidak dapat diakses")
    except requests.exceptions.ConnectionError:
        print(f"[-] Tidak dapat terhubung ke {base_url}")
    except Exception as e:
        print(f"[!] Error: {e}")
    return {"url": base_url, "accessible": False}


def scan_remote(host, ports):
    """Scan for exposed Docker API on remote host."""
    print(f"\n[*] Memindai Docker API di {host}...")
    for port in ports:
        try:
            url = f"http://{host}:{port}"
            resp = requests.get(f"{url}/v1.43/info", timeout=3)
            if resp.status_code == 200:
                print(f"[+] Docker API terpapar di http://{host}:{port}")
                print(f"    Versi: {resp.json().get('ServerVersion', '?')}")
            elif resp.status_code == 401:
                print(f"[*] Docker API terpapar (auth required) di http://{host}:{port}")
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass

        try:
            url_tls = f"https://{host}:{port}"
            requests.get(f"{url_tls}/v1.43/info", timeout=3, verify=False)
        except requests.exceptions.SSLError:
            print(f"[*] Docker API TLS terpapar di https://{host}:{port} (self-signed)")
        except Exception:
            pass


def enum_containers(base_url):
    """Enumerate containers (running + stopped)."""
    print("\n--- Enumerasi Container ---")
    if base_url.startswith("unix://"):
        containers = unix_sock_request("/containers/json?all=true")
    else:
        try:
            resp = requests.get(
                f"{base_url}/v1.43/containers/json?all=true", timeout=10, verify=False
            )
            containers = resp.json() if resp.status_code == 200 else None
        except Exception:
            containers = None

    if not containers:
        print("[-] Tidak bisa enumerasi containers")
        return []

    running = [c for c in containers if c.get("State") == "running"]
    stopped = [c for c in containers if c.get("State") != "running"]
    print(
        f"[+] Total containers: {len(containers)} (running={len(running)}, stopped={len(stopped)})\n"
    )

    risks = []
    for c in containers:
        name = c.get("Names", ["?"])[0].lstrip("/")
        image = c.get("Image", "?")
        state = c.get("State", "?")
        status = c.get("Status", "?")

        if state == "running":
            details = inspect_container(base_url, c["Id"])
            if details:
                host_config = details.get("HostConfig", {})
                is_privileged = host_config.get("Privileged", False)
                pid_mode = host_config.get("PidMode", "")
                net_mode = host_config.get("NetworkMode", "")
                mounts = host_config.get("Mounts", [])
                cap_add = host_config.get("CapAdd", [])

                has_docker_sock = any("/var/run/docker.sock" in m.get("Source", "") for m in mounts)
                host_net = net_mode == "host"
                host_pid = pid_mode == "host"

                flags = []
                if is_privileged:
                    flags.append("[!] PRIVILEGED")
                    risks.append(f"{name}: privileged container")
                if host_net:
                    flags.append("[!] host-network")
                    risks.append(f"{name}: host network namespace")
                if host_pid:
                    flags.append("[!] host-pid")
                    risks.append(f"{name}: host PID namespace")
                if has_docker_sock:
                    flags.append("[!] docker-sock-mounted")
                    risks.append(f"{name}: Docker socket mounted")
                if "SYS_ADMIN" in cap_add:
                    flags.append("[!] SYS_ADMIN-cap")
                    risks.append(f"{name}: SYS_ADMIN capability")
                if "NET_ADMIN" in cap_add:
                    flags.append("[!] NET_ADMIN-cap")
                if "SYS_PTRACE" in cap_add:
                    flags.append("[!] SYS_PTRACE-cap")
                if "SYS_RAWIO" in cap_add:
                    flags.append("[!] SYS_RAWIO-cap")

                risk_str = " " + " ".join(flags) if flags else ""
                pfx = "[!]" if flags else "[*]"
                print(f"  {pfx} {name} ({image}) | {state}{risk_str}")
            else:
                print(f"  [*] {name} ({image}) | {state}")
        else:
            print(f"  [*] {name} ({image}) | {state} | {status}")

    if risks:
        print(f"\n[!] Ditemukan {len(risks)} risiko keamanan:")
        for r in risks:
            print(f"  [!] {r}")
    else:
        print("\n[+] Tidak ditemukan container dengan risiko tinggi")

    return containers


def inspect_container(base_url, container_id):
    """Get detailed container info."""
    if base_url.startswith("unix://"):
        return unix_sock_request(f"/containers/{container_id}/json")
    try:
        resp = requests.get(
            f"{base_url}/v1.43/containers/{container_id}/json",
            timeout=10,
            verify=False,
        )
        return resp.json() if resp.status_code == 200 else None
    except Exception:
        return None


def enum_images(base_url):
    """Enumerate images."""
    print("\n--- Enumerasi Images ---")
    if base_url.startswith("unix://"):
        images = unix_sock_request("/images/json")
    else:
        try:
            resp = requests.get(f"{base_url}/v1.43/images/json", timeout=10, verify=False)
            images = resp.json() if resp.status_code == 200 else None
        except Exception:
            images = None

    if images:
        print(f"[+] Images: {len(images)}")
        for img in images[:20]:
            tags = img.get("RepoTags", ["<none>"])
            size_mb = img.get("Size", 0) // (1024 * 1024)
            print(f"  [*] {tags[0]} ({size_mb}MB)")
        if len(images) > 20:
            print(f"  ... dan {len(images) - 20} images lainnya")
    else:
        print("[-] Tidak bisa enumerasi images")
    return images


def enum_volumes(base_url):
    """Enumerate volumes."""
    print("\n--- Enumerasi Volumes ---")
    if base_url.startswith("unix://"):
        volumes = unix_sock_request("/volumes")
    else:
        try:
            resp = requests.get(f"{base_url}/v1.43/volumes", timeout=10, verify=False)
            volumes = resp.json() if resp.status_code == 200 else None
        except Exception:
            volumes = None

    if volumes:
        vols = volumes if isinstance(volumes, list) else volumes.get("Volumes", [])
        print(f"[+] Volumes: {len(vols)}")
        for v in vols[:20]:
            name = v.get("Name", "?")
            driver = v.get("Driver", "?")
            print(f"  [*] {name} (driver={driver})")
        if len(vols) > 20:
            print(f"  ... dan {len(vols) - 20} volumes lainnya")
    else:
        print("[-] Tidak bisa enumerasi volumes")
    return volumes


def enum_networks(base_url):
    """Enumerate networks."""
    print("\n--- Enumerasi Networks ---")
    if base_url.startswith("unix://"):
        networks = unix_sock_request("/networks")
    else:
        try:
            resp = requests.get(f"{base_url}/v1.43/networks", timeout=10, verify=False)
            networks = resp.json() if resp.status_code == 200 else None
        except Exception:
            networks = None

    if networks:
        print(f"[+] Networks: {len(networks)}")
        for n in networks:
            name = n.get("Name", "?")
            driver = n.get("Driver", "?")
            scope = n.get("Scope", "?")
            internal = n.get("Internal", False)
            print(f"  [*] {name} (driver={driver}, scope={scope}, internal={internal})")
    else:
        print("[-] Tidak bisa enumerasi networks")
    return networks


def detect_local_docker():
    """Detect and check local Docker installation."""
    print("[*] Memeriksa instalasi Docker lokal\n")

    if os.path.exists(DOCKER_SOCK):
        print(f"[+] Docker socket ditemukan: {DOCKER_SOCK}")
        result = check_docker_api("unix://" + DOCKER_SOCK)
        if result["accessible"]:
            return result
    else:
        print(f"[-] Docker socket tidak ditemukan ({DOCKER_SOCK})")

    for port in COMMON_DOCKER_PORTS:
        try:
            url = f"http://localhost:{port}"
            resp = requests.get(f"{url}/v1.43/info", timeout=2)
            if resp.status_code in (200, 401):
                print(f"[+] Docker API ditemukan di {url}")
                result = check_docker_api(url)
                if result["accessible"]:
                    return result
                break
        except Exception:
            pass

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Docker Enumeration & Security Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python docker_enum.py
  python docker_enum.py --host 192.168.1.100 --port 2375
  python docker_enum.py --host docker.example.com --port 2376 --tls
  python docker_enum.py --deep
        """,
    )
    parser.add_argument("--host", help="Host remote Docker daemon")
    parser.add_argument("--port", type=int, default=2375, help="Port Docker API (default: 2375)")
    parser.add_argument("--tls", action="store_true", help="Gunakan HTTPS/TLS")
    parser.add_argument("--deep", action="store_true", help="Analisis keamanan mendalam")
    parser.add_argument("--output", help="Simpan hasil ke file JSON")
    args = parser.parse_args()

    print("=" * 60)
    print("  Docker Enumeration & Security Checker")
    print("=" * 60)

    results = {}

    if args.host:
        scan_remote(args.host, [args.port, 2376, 4243, 5555])
        protocol = "https" if args.tls else "http"
        base = f"{protocol}://{args.host}:{args.port}"
        result = check_docker_api(base, verify_tls=not args.tls or True)
    else:
        result = detect_local_docker()

    if result and result.get("accessible"):
        base_url = result["url"]
        results["info"] = result.get("info", {})
        results["containers"] = enum_containers(base_url)
        results["images"] = enum_images(base_url)
        results["volumes"] = enum_volumes(base_url)
        results["networks"] = enum_networks(base_url)

        if args.deep and base_url.startswith("unix://"):
            print("\n--- Analisis Keamanan Mendalam ---")
            sens_files = [
                "/etc/shadow",
                "/etc/passwd",
                "/root/.ssh/id_rsa",
                "/proc/1/cgroup",
                "/proc/1/mountinfo",
            ]
            print("[*] Memeriksa akses file sensitif dari container...")
            for fpath in sens_files:
                if os.path.exists(fpath):
                    print(f"  [*] {fpath} - dapat diakses dari host")
    elif result and result.get("auth") == "required":
        print("\n[*] API memerlukan autentikasi. Gunakan kredensial yang sesuai.")
    else:
        print("\n[-] Docker API tidak ditemukan atau tidak dapat diakses")
        print("[*] Coba periksa: ")
        print("    - Apakah Docker daemon berjalan?")
        print("    - Apakah port 2375/2376 diekspos?")
        print("    - Apakah socket /var/run/docker.sock ada?")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Hasil disimpan ke: {args.output}")

    print("\n[*] Selesai.")


if __name__ == "__main__":
    main()
