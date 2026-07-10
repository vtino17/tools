#!/usr/bin/env python3
"""
TCP Port Forwarder - Pemforward lalu lintas TCP sederhana (local, remote, SOCKS).

Usage:
  python port_forward.py --mode local --port 8080 --target 192.168.1.10 --remote-port 80
  python port_forward.py --mode remote --bind 0.0.0.0 --port 2222 --target 10.0.0.5 --remote-port 22
  python port_forward.py --mode socks --port 1080
"""

import argparse
import select
import socket
import struct
import sys
import threading
import time

BANNER = r"""
  ___           _     ___                               _             
 | _ \___  _ _ | |_  | __| _ ___ __  _ _ _ ___  __ _ __| | ___  _ _  
 |  _/ _ \| ' \|  _| | _| '_/ _ \\ \/ | '_/ _ \ \ / _` / _` |/ -_)| '_| 
 |_| \___/|_||_|\__| |_||_| \___/\___/|_| \___/_\_\\\__,_\__,_|\___||_|  
"""

SOCKS_VERSION = 5
SOCKS_NO_AUTH = 0
SOCKS_AUTH_USERPASS = 2
SOCKS_NO_ACCEPTABLE = 0xFF
SOCKS_CMD_CONNECT = 1
SOCKS_ATYP_IPV4 = 1
SOCKS_ATYP_DOMAIN = 3
SOCKS_ATYP_IPV6 = 4
SOCKS_REPLY_SUCCEEDED = 0
SOCKS_REPLY_GENERAL_FAILURE = 1


def print_info(msg):
    print(f"[*] {msg}")


def print_success(msg):
    print(f"[+] {msg}")


def print_error(msg):
    print(f"[!] {msg}")


def pipe_sockets(src, dst, buf_size=8192):
    try:
        while True:
            data = src.recv(buf_size)
            if not data:
                break
            try:
                dst.sendall(data)
            except Exception:
                break
    except Exception:
        pass
    finally:
        try:
            src.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def relay_connection(client_sock, target_host, target_port):
    remote_sock = None
    try:
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.settimeout(10)
        remote_sock.connect((target_host, target_port))
        remote_sock.settimeout(None)
    except Exception as e:
        print_error(f"Gagal koneksi ke {target_host}:{target_port} - {e}")
        try:
            client_sock.close()
        except Exception:
            pass
        return

    print_success(f"Terowongan: {client_sock.getpeername()} <-> {target_host}:{target_port}")

    t1 = threading.Thread(target=pipe_sockets, args=(client_sock, remote_sock))
    t2 = threading.Thread(target=pipe_sockets, args=(remote_sock, client_sock))
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    t1.join(300)
    t2.join(300)

    try:
        client_sock.close()
    except Exception:
        pass
    try:
        remote_sock.close()
    except Exception:
        pass


def mode_local(bind_addr, local_port, target_host, remote_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, 15, 1) if hasattr(socket, "SO_REUSEPORT") else None
    try:
        server.bind((bind_addr, local_port))
    except Exception as e:
        print_error(f"Gagal bind {bind_addr}:{local_port} - {e}")
        return
    server.listen(50)
    print_success(f"Local forward: {bind_addr}:{local_port} -> {target_host}:{remote_port}")
    print_info("Menunggu koneksi... (Ctrl+C untuk berhenti)")

    try:
        while True:
            client, addr = server.accept()
            print_info(f"Koneksi masuk dari {addr}")
            t = threading.Thread(target=relay_connection, args=(client, target_host, remote_port))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print_info("Dihentikan oleh pengguna.")
    finally:
        server.close()


def mode_remote(bind_addr, local_port, server_host, server_port):
    socks = []
    def handle_client(client, addr):
        try:
            while True:
                data = client.recv(8192)
                if not data:
                    break
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((bind_addr, local_port))
    except Exception as e:
        print_error(f"Gagal bind {bind_addr}:{local_port} - {e}")
        return
    listener.listen(50)

    print_success(f"Remote forward: {server_host}:{server_port} -> {bind_addr}:{local_port}")
    print_info("Menunggu koneksi... (Ctrl+C untuk berhenti)")

    def accept_loop():
        try:
            while True:
                client, addr = listener.accept()
                print_info(f"Remote client dari {addr}")
                t = threading.Thread(target=handle_client, args=(client, addr))
                t.daemon = True
                t.start()
        except Exception:
            pass

    accept_thread = threading.Thread(target=accept_loop)
    accept_thread.daemon = True
    accept_thread.start()

    def pump_server():
        while True:
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((server_host, server_port))
                while True:
                    data = remote.recv(8192)
                    if not data:
                        break
            except Exception:
                time.sleep(5)
            finally:
                try:
                    remote.close()
                except Exception:
                    pass

    pump_thread = threading.Thread(target=pump_server)
    pump_thread.daemon = True
    pump_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print_info("Dihentikan oleh pengguna.")
    finally:
        listener.close()


class SocksProxy:
    def __init__(self, bind_addr, local_port):
        self.bind_addr = bind_addr
        self.local_port = local_port

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.bind_addr, self.local_port))
        except Exception as e:
            print_error(f"Gagal bind SOCKS {self.bind_addr}:{self.local_port} - {e}")
            return
        server.listen(50)
        print_success(f"SOCKS5 proxy berjalan di {self.bind_addr}:{self.local_port}")
        print_info("Menunggu koneksi SOCKS... (Ctrl+C untuk berhenti)")

        try:
            while True:
                client, addr = server.accept()
                t = threading.Thread(target=self.handle_socks_client, args=(client, addr))
                t.daemon = True
                t.start()
        except KeyboardInterrupt:
            print_info("Dihentikan oleh pengguna.")
        finally:
            server.close()

    def handle_socks_client(self, client, addr):
        try:
            client.settimeout(30)
            ver, nmethods = client.recv(2)
            if ver != SOCKS_VERSION:
                client.close()
                return
            methods = client.recv(nmethods)
            client.sendall(struct.pack("!BB", SOCKS_VERSION, SOCKS_NO_AUTH))
            ver, cmd, rsv, atyp = struct.unpack("!BBBB", client.recv(4))
            if cmd != SOCKS_CMD_CONNECT:
                self._send_reply(client, SOCKS_REPLY_GENERAL_FAILURE)
                client.close()
                return
            if atyp == SOCKS_ATYP_IPV4:
                target_addr = socket.inet_ntoa(client.recv(4))
            elif atyp == SOCKS_ATYP_DOMAIN:
                domain_len = ord(client.recv(1))
                target_addr = client.recv(domain_len).decode()
            elif atyp == SOCKS_ATYP_IPV6:
                target_addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
            else:
                self._send_reply(client, SOCKS_REPLY_GENERAL_FAILURE)
                client.close()
                return
            target_port = struct.unpack("!H", client.recv(2))[0]
        except Exception as e:
            try:
                client.close()
            except Exception:
                pass
            return

        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(15)
            remote.connect((target_addr, target_port))
            bind_addr = remote.getsockname()
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, SOCKS_REPLY_SUCCEEDED, 0,
                                SOCKS_ATYP_IPV4,
                                struct.unpack("!I", socket.inet_aton(bind_addr[0]))[0],
                                bind_addr[1])
            client.sendall(reply)
            remote.settimeout(None)
        except Exception as e:
            print_error(f"Gagal SOCKS connect ke {target_addr}:{target_port} - {e}")
            self._send_reply(client, SOCKS_REPLY_GENERAL_FAILURE)
            client.close()
            return

        print_success(f"SOCKS tunnel: {addr} -> {target_addr}:{target_port}")

        t1 = threading.Thread(target=pipe_sockets, args=(client, remote))
        t2 = threading.Thread(target=pipe_sockets, args=(remote, client))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join(300)
        t2.join(300)
        try:
            client.close()
        except Exception:
            pass
        try:
            remote.close()
        except Exception:
            pass

    def _send_reply(self, sock, reply_code):
        try:
            sock.sendall(struct.pack("!BBBBIH", SOCKS_VERSION, reply_code, 0,
                                     SOCKS_ATYP_IPV4, 0, 0))
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="TCP Port Forwarder - Pemforward lalu lintas TCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--mode", choices=["local", "remote", "socks"], required=True,
                        help="Mode forwarding (local/remote/socks)")
    parser.add_argument("--bind", default="0.0.0.0", help="Alamat bind lokal (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, required=True, help="Port lokal")
    parser.add_argument("--target", help="Host target (untuk mode local/remote)")
    parser.add_argument("--remote-port", type=int, help="Port remote target (untuk mode local)")

    args = parser.parse_args()

    print(BANNER)
    print_info(f"Mode: {args.mode.upper()}")

    if args.mode == "local":
        if not args.target or not args.remote_port:
            print_error("Mode local butuh --target dan --remote-port")
            sys.exit(1)
        mode_local(args.bind, args.port, args.target, args.remote_port)
    elif args.mode == "remote":
        if not args.target:
            print_error("Mode remote butuh --target")
            sys.exit(1)
        mode_remote(args.bind, args.port, args.target, args.remote_port or 2222)
    elif args.mode == "socks":
        proxy = SocksProxy(args.bind, args.port)
        proxy.run()


if __name__ == "__main__":
    main()
