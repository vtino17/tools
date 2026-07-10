#!/usr/bin/env python3
"""
LDAP Enumeration Tool.

Melakukan enumerasi LDAP pada target domain controller.
Mendukung anonymous bind, authenticated bind, dan LDAPS (SSL).

Mengekstrak: naming contexts, root DSE, users, groups, computers,
OUs, domain admins, service accounts, password policy, SASL mechanisms.

Menggunakan python-ldap jika tersedia, dengan fallback pure-socket BER/DER.

Usage:
    python ldap_scanner.py --target 192.168.1.10
    python ldap_scanner.py --target dc.example.com --username admin --password P@ss
    python ldap_scanner.py --target dc.example.com --ssl
    python ldap_scanner.py --target dc.example.com --filter "(objectClass=user)"
"""

import argparse
import socket
import ssl
import sys
from collections import defaultdict

try:
    import ldap
    from ldap.controls import SimplePagedResultsControl
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False


def log_info(msg: str) -> None:
    print(f"[*] {msg}")


def log_success(msg: str) -> None:
    print(f"[+] {msg}")


def log_error(msg: str) -> None:
    print(f"[!] {msg}")


def log_warn(msg: str) -> None:
    print(f"[-] {msg}")


DEFAULT_ATTRIBUTES = {
    "user": [
        "cn", "sAMAccountName", "userPrincipalName", "displayName",
        "mail", "description", "memberOf", "userAccountControl",
        "lastLogon", "pwdLastSet", "whenCreated", "whenChanged",
        "distinguishedName", "objectSid", "primaryGroupID",
    ],
    "group": [
        "cn", "sAMAccountName", "description", "member", "memberOf",
        "groupType", "distinguishedName", "whenCreated",
    ],
    "computer": [
        "cn", "sAMAccountName", "operatingSystem", "operatingSystemVersion",
        "dNSHostName", "lastLogonTimestamp", "whenCreated", "distinguishedName",
    ],
    "organizationalUnit": [
        "ou", "name", "description", "distinguishedName", "whenCreated",
    ],
    "domain": [
        "name", "distinguishedName", "objectSid", "creationTime",
        "domainFunctionality", "forestFunctionality", "lockoutDuration",
        "lockOutObservationWindow", "lockoutThreshold", "maxPwdAge",
        "minPwdAge", "minPwdLength", "pwdHistoryLength", "pwdProperties",
    ],
}


# ---------------------------------------------------------------------------
# Raw BER/DER encoding/decoding helpers (pure-socket fallback)
# ---------------------------------------------------------------------------

def ber_decode_length(data: bytes, pos: int) -> tuple[int, int]:
    length = data[pos]
    pos += 1
    if length < 128:
        return length, pos
    num_octets = length & 0x7F
    length = 0
    for _ in range(num_octets):
        length = (length << 8) | data[pos]
        pos += 1
    return length, pos


def ber_decode_integer(data: bytes, pos: int) -> tuple[int, int]:
    assert data[pos] == 0x02, f"Expected INTEGER tag, got {data[pos]:#x}"
    pos += 1
    length, pos = ber_decode_length(data, pos)
    value = int.from_bytes(data[pos:pos + length], "big", signed=True)
    return value, pos + length


def ber_decode_string(data: bytes, pos: int) -> tuple[str, int]:
    assert data[pos] in (0x04, 0x0C), f"Expected string tag, got {data[pos]:#x}"
    pos += 1
    length, pos = ber_decode_length(data, pos)
    value = data[pos:pos + length].decode("utf-8", errors="replace")
    return value, pos + length


def ber_decode_sequence(data: bytes, pos: int) -> tuple[bytes, int]:
    assert data[pos] == 0x30, f"Expected SEQUENCE tag, got {data[pos]:#x}"
    pos += 1
    length, pos = ber_decode_length(data, pos)
    return data[pos:pos + length], pos + length


def encode_ber_length(length: int) -> bytes:
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


def encode_ber_integer(value: int) -> bytes:
    result = b""
    n = value
    while n:
        result = bytes([n & 0xFF]) + result
        n >>= 8
    if not result:
        result = b"\x00"
    return b"\x02" + encode_ber_length(len(result)) + result


def encode_ber_octet_string(data: bytes) -> bytes:
    return b"\x04" + encode_ber_length(len(data)) + data


def encode_ber_sequence(data: bytes) -> bytes:
    return b"\x30" + encode_ber_length(len(data)) + data


def build_ldap_bind_request(version: int = 3, dn: str = "", password: str = "") -> bytes:
    version_tlv = encode_ber_integer(version)
    dn_bytes = dn.encode("utf-8")
    name_tlv = encode_ber_octet_string(dn_bytes)
    auth_tlv = b"\xa0" + encode_ber_length(2) + encode_ber_octet_string(
        password.encode("utf-8") if password else b""
    )
    bind_proto = version_tlv + name_tlv + auth_tlv
    bind_pdu = b"\x60" + encode_ber_length(len(bind_proto)) + bind_proto
    message_id = encode_ber_integer(1)
    ldap_msg = encode_ber_sequence(message_id + bind_pdu)
    return ldap_msg


def build_ldap_search_request(
    base_dn: str,
    filter_str: str,
    scope: int = 2,
    attributes: list[str] | None = None,
    msg_id: int = 2,
) -> bytes:
    base_tlv = encode_ber_octet_string(base_dn.encode("utf-8"))
    scope_tlv = b"\x0a\x01" + bytes([scope])
    deref_tlv = b"\x0a\x01\x00"
    sizelimit_tlv = b"\x02\x01\x00"
    timelimit_tlv = b"\x02\x01\x00"
    typesonly_tlv = b"\x01\x01\x00"

    filter_bytes = _encode_ldap_filter(filter_str)
    attrs_enc = b""
    if attributes:
        for attr in attributes:
            attrs_enc += encode_ber_octet_string(attr.encode("utf-8"))
    attrs_tlv = encode_ber_sequence(attrs_enc)

    search_proto = base_tlv + scope_tlv + deref_tlv + sizelimit_tlv
    search_proto += timelimit_tlv + typesonly_tlv + filter_bytes + attrs_tlv
    search_pdu = b"\x63" + encode_ber_length(len(search_proto)) + search_proto
    message_id = encode_ber_integer(msg_id)
    return encode_ber_sequence(message_id + search_pdu)


def _encode_ldap_filter(filter_str: str) -> bytes:
    filter_bytes = filter_str.encode("utf-8")
    present = b"\x87" + encode_ber_length(len(filter_bytes)) + filter_bytes
    filter_block = b"\xa0" + encode_ber_length(len(present)) + present
    return filter_block


def decode_ldap_search_result(data: bytes) -> list[dict[str, list[str]]]:
    entries = []
    try:
        pos = 0
        outer_seq, pos = ber_decode_sequence(data, pos)
        inner_seq, pos = ber_decode_sequence(outer_seq, pos)

        try:
            protocol_op = inner_seq[0]
        except IndexError:
            return entries

        if protocol_op == 0x64:
            pos = 0
            _len, pos = ber_decode_length(inner_seq, pos)
            op_data = inner_seq[pos:pos + _len]
            op_pos = 0
            dn, op_pos = ber_decode_string(op_data, op_pos)

            attrs_seq, op_pos = ber_decode_sequence(op_data, op_pos)
            attrs_pos = 0
            entry: dict[str, list[str]] = {"dn": dn}
            while attrs_pos < len(attrs_seq):
                attr_seq, attrs_pos = ber_decode_sequence(attrs_seq, attrs_pos)
                ap = 0
                attr_name, ap = ber_decode_string(attr_seq, ap)
                vals_set, ap = ber_decode_sequence(attr_seq, ap)
                vp = 0
                vals = []
                while vp < len(vals_set):
                    val, vp = ber_decode_string(vals_set, vp)
                    vals.append(val)
                entry[attr_name] = vals
            entries.append(entry)
    except Exception:
        pass
    return entries


def raw_ldap_bind(target: str, port: int, use_ssl: bool, dn: str = "", password: str = "") -> bool:
    try:
        sock = socket.create_connection((target, port), timeout=10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=target)

        request = build_ldap_bind_request(version=3, dn=dn, password=password)
        sock.send(request)
        response = sock.recv(4096)
        sock.close()

        if not response:
            return False

        pos = 0
        try:
            outer_seq, pos = ber_decode_sequence(response, pos)
            inner_seq, pos = ber_decode_sequence(outer_seq, pos)
        except Exception:
            return False

        try:
            _ = inner_seq[0]
            result_pos = 1
            _len, result_pos = ber_decode_length(inner_seq, result_pos)
            result_code_byte = inner_seq[result_pos + 1] if result_pos + 1 < len(inner_seq) else 0
            return result_code_byte == 0
        except Exception:
            return False
    except Exception:
        return False


def raw_ldap_search(
    target: str, port: int, use_ssl: bool, base_dn: str, filter_str: str,
    dn: str = "", password: str = "", attributes: list[str] | None = None,
) -> list[dict[str, list[str]]]:
    try:
        sock = socket.create_connection((target, port), timeout=10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=target)

        bind_req = build_ldap_bind_request(version=3, dn=dn, password=password)
        sock.send(bind_req)
        bind_resp = sock.recv(4096)
        if not bind_resp:
            sock.close()
            return []

        search_req = build_ldap_search_request(base_dn, filter_str, scope=2, attributes=attributes, msg_id=2)
        sock.send(search_req)
        all_data = b""
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                all_data += chunk
            except socket.timeout:
                break
        sock.close()

        return decode_ldap_search_result(all_data)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# python-ldap based scanner
# ---------------------------------------------------------------------------

def search_paged(conn, base_dn: str, filter_str: str, attrs: list[str]) -> list[dict]:
    results = []
    try:
        lc = SimplePagedResultsControl(size=500, cookie="")
        msgid = conn.search_ext(base_dn, ldap.SCOPE_SUBTREE, filter_str, attrs, serverctrls=[lc])
        while True:
            rtype, rdata, rmsgid, serverctrls = conn.result3(msgid)
            for _dn_entry, entry in rdata:
                item: dict = {}
                for k, v in entry.items():
                    item[k] = [x.decode() if isinstance(x, bytes) else str(x) for x in v]
                results.append(item)
            pctrls = [c for c in serverctrls if c.controlType == SimplePagedResultsControl.controlType]
            if not pctrls or not pctrls[0].cookie:
                break
            lc.cookie = pctrls[0].cookie
            msgid = conn.search_ext(base_dn, ldap.SCOPE_SUBTREE, filter_str, attrs, serverctrls=[lc])
    except Exception:
        try:
            raw = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str, attrs)
            for dn_entry, entry in raw:
                item = {"dn": dn_entry}
                for k, v in entry.items():
                    item[k] = [x.decode() if isinstance(x, bytes) else str(x) for x in v]
                results.append(item)
        except Exception:
            pass
    return results


def scan_python_ldap(args: argparse.Namespace) -> dict:
    port = 636 if args.ssl else (args.port or 389)
    proto = "ldaps" if args.ssl else "ldap"
    uri = f"{proto}://{args.target}:{port}"

    log_info(f"Menghubungkan ke {uri}...")

    conn = ldap.initialize(uri)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
    conn.set_option(ldap.OPT_TIMEOUT, 10)

    result = {
        "target": args.target,
        "authenticated": False,
        "root_dse": {},
        "naming_contexts": [],
        "supported_extensions": [],
        "domain_info": {},
        "users": [],
        "groups": [],
        "computers": [],
        "ous": [],
        "domain_admins": [],
        "service_accounts": [],
        "password_policy": {},
        "sasl_mechanisms": [],
    }

    try:
        if args.username and args.password:
            dn = args.username if "=" in args.username else f"{args.username}@{args.target}"
            log_info(f"Mencoba bind sebagai: {dn}")
            conn.simple_bind_s(dn, args.password)
            result["authenticated"] = True
            log_success("Bind authenticated BERHASIL")
        else:
            log_info("Mencoba anonymous bind...")
            try:
                conn.simple_bind_s("", "")
                log_success("Anonymous bind BERHASIL")
            except ldap.LDAPError as e:
                log_error(f"Anonymous bind GAGAL: {e}")
                return result

        root_dse = conn.search_s(
            "", ldap.SCOPE_BASE, "(objectClass=*)",
            ["*", "+", "supportedSASLMechanisms", "supportedExtension"],
        )
        if root_dse:
            dse_entry = root_dse[0][1]
            for k, v in dse_entry.items():
                decoded = [x.decode() if isinstance(x, bytes) else str(x) for x in v]
                result["root_dse"][k] = decoded

            naming = dse_entry.get("namingContexts", [])
            result["naming_contexts"] = [nc.decode() for nc in naming]
            log_success(f"Naming contexts: {len(result['naming_contexts'])} ditemukan")

            supported_ext = dse_entry.get("supportedExtension", [])
            result["supported_extensions"] = [e.decode() for e in supported_ext]

            sasl = dse_entry.get("supportedSASLMechanisms", [])
            result["sasl_mechanisms"] = [s.decode() for s in sasl]
            if result["sasl_mechanisms"]:
                log_success(f"SASL mechanisms: {result['sasl_mechanisms']}")

        base_dn = args.base or (result["naming_contexts"][0] if result["naming_contexts"] else "")
        if not base_dn:
            log_warn("Tidak dapat menentukan base DN")
            return result

        log_info(f"Menggunakan base DN: {base_dn}")

        search_types = {
            "users": ("(objectClass=user)", DEFAULT_ATTRIBUTES["user"]),
            "groups": ("(objectClass=group)", DEFAULT_ATTRIBUTES["group"]),
            "computers": ("(objectClass=computer)", DEFAULT_ATTRIBUTES["computer"]),
            "ous": ("(objectClass=organizationalUnit)", DEFAULT_ATTRIBUTES["organizationalUnit"]),
        }

        for label, (filter_str, attrs) in search_types.items():
            log_info(f"Mencari {label}...")
            try:
                entries = search_paged(conn, base_dn, filter_str, attrs)
                result[label] = entries
                log_success(f"  {label}: {len(entries)} ditemukan")
            except Exception as e:
                log_warn(f"  {label}: {e}")

        log_info("Mencari Domain Admins...")
        try:
            da_filter = "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,{}))".format(base_dn)
            da_entries = search_paged(conn, base_dn, da_filter, DEFAULT_ATTRIBUTES["user"])
            result["domain_admins"] = da_entries
            if da_entries:
                log_success(f"  Domain Admins: {len(da_entries)} ditemukan")
        except Exception:
            pass

        log_info("Mencari Service Accounts...")
        try:
            sa_entries = search_paged(conn, base_dn, "(&(objectClass=user)(servicePrincipalName=*))", DEFAULT_ATTRIBUTES["user"])
            result["service_accounts"] = sa_entries
            if sa_entries:
                log_success(f"  Service accounts: {len(sa_entries)} ditemukan")
        except Exception:
            pass

        log_info("Mengambil password policy...")
        try:
            pp = conn.search_s(base_dn, ldap.SCOPE_BASE, "(objectClass=*)", DEFAULT_ATTRIBUTES["domain"])
            if pp:
                entry = pp[0][1]
                result["password_policy"] = {
                    k: [x.decode() if isinstance(x, bytes) else str(x) for x in v]
                    for k, v in entry.items()
                    if k in DEFAULT_ATTRIBUTES["domain"]
                }
                log_success("Password policy ditemukan")
        except Exception:
            pass

        if args.filter:
            log_info(f"Custom filter: {args.filter}")
            try:
                custom = search_paged(conn, base_dn, args.filter, ["*"])
                result["custom_filter"] = custom
                log_success(f"  Custom: {len(custom)} hasil")
            except Exception as e:
                log_error(f"  Custom filter error: {e}")

    except ldap.LDAPError as e:
        log_error(f"Error LDAP: {e}")
    finally:
        conn.unbind_s()

    return result


def scan_raw_socket(args: argparse.Namespace) -> dict:
    port = 636 if args.ssl else (args.port or 389)
    result = {
        "target": args.target,
        "authenticated": False,
        "naming_contexts": [],
        "users": [],
        "groups": [],
        "computers": [],
        "ous": [],
    }

    dn = ""
    password = ""
    if args.username and args.password:
        parts = args.target.split(".")
        guessed_dn = f"cn={args.username},dc={',dc='.join(parts)}"
        dn = args.username if "=" in args.username else guessed_dn
        password = args.password

    log_info(f"Raw socket bind ke {args.target}:{port}...")
    bind_ok = raw_ldap_bind(args.target, port, args.ssl, dn, password)
    if not bind_ok:
        log_error("Bind gagal melalui raw socket")
        return result

    log_success("Bind BERHASIL via raw socket")

    guessed_nc = f"dc={',dc='.join(args.target.split('.'))}"
    entries = raw_ldap_search(
        args.target, port, args.ssl, "", "(objectClass=*)",
        dn, password, ["namingContexts"],
    )
    if entries and entries[0].get("namingContexts"):
        result["naming_contexts"] = entries[0].get("namingContexts", [])
        log_success(f"Naming contexts: {result['naming_contexts']}")

    base_dn = args.base or (result["naming_contexts"][0] if result["naming_contexts"] else guessed_nc)

    searches = [
        ("users", "(objectClass=user)", ["cn", "sAMAccountName", "mail"]),
        ("groups", "(objectClass=group)", ["cn", "sAMAccountName"]),
        ("computers", "(objectClass=computer)", ["cn", "dNSHostName"]),
    ]

    for label, filter_str, attrs in searches:
        log_info(f"Mencari {label}...")
        entries_found = raw_ldap_search(args.target, port, args.ssl, base_dn, filter_str, dn, password, attrs)
        result[label] = entries_found
        log_success(f"  {label}: {len(entries_found)} ditemukan")

    return result


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def display_results(result: dict) -> None:
    print(f"\n{'=' * 60}")
    print(f"  HASIL ENUMERASI LDAP")
    print(f"{'=' * 60}")
    print(f"  Target        : {result['target']}")
    print(f"  Authenticated : {'Ya' if result.get('authenticated') else 'Tidak (anonymous)'}")
    print(f"{'=' * 60}")

    if result.get("root_dse"):
        print(f"\n  [ROOT DSE]")
        for k, v in result["root_dse"].items():
            if k not in ("namingContexts", "supportedExtension", "supportedSASLMechanisms"):
                print(f"    {k}: {v}")

    if result.get("naming_contexts"):
        print(f"\n  [NAMING CONTEXTS]")
        for nc in result["naming_contexts"]:
            print(f"    - {nc}")

    if result.get("supported_extensions"):
        print(f"\n  [SUPPORTED EXTENSIONS] ({len(result['supported_extensions'])})")
        for ext in result["supported_extensions"][:10]:
            print(f"    - {ext}")
        if len(result["supported_extensions"]) > 10:
            print(f"    ... dan {len(result['supported_extensions']) - 10} lainnya")

    if result.get("sasl_mechanisms"):
        print(f"\n  [SASL MECHANISMS]")
        for m in result["sasl_mechanisms"]:
            print(f"    - {m}")

    for label in ["users", "groups", "computers", "ous"]:
        entries = result.get(label, [])
        if entries:
            print(f"\n  [{label.upper()}] ({len(entries)})")
            for entry in entries[:15]:
                dn = entry.get("dn", str(entry))
                name = entry.get("cn", entry.get("sAMAccountName", entry.get("ou")))
                if isinstance(name, list):
                    name = name[0] if name else ""
                extra = f" ({name})" if name else ""
                print(f"    - {dn}{extra}")
            if len(entries) > 15:
                print(f"    ... dan {len(entries) - 15} lainnya")

    if result.get("domain_admins"):
        print(f"\n  [DOMAIN ADMINS] ({len(result['domain_admins'])})")
        for da in result["domain_admins"][:10]:
            dn = da.get("dn", "")
            name = da.get("sAMAccountName", da.get("cn", ""))
            if isinstance(name, list):
                name = name[0] if name else ""
            print(f"    - {name}  ({dn})")
        if len(result["domain_admins"]) > 10:
            print(f"    ... dan {len(result['domain_admins']) - 10} lainnya")

    if result.get("service_accounts"):
        print(f"\n  [SERVICE ACCOUNTS] ({len(result['service_accounts'])})")
        for sa in result["service_accounts"][:15]:
            dn = sa.get("dn", "")
            name = sa.get("sAMAccountName", sa.get("cn", ""))
            if isinstance(name, list):
                name = name[0] if name else ""
            print(f"    - {name}  ({dn})")
        if len(result["service_accounts"]) > 15:
            print(f"    ... dan {len(result['service_accounts']) - 15} lainnya")

    if result.get("password_policy"):
        pp = result["password_policy"]
        print(f"\n  [PASSWORD POLICY]")
        pp_labels = {
            "minPwdLength": "Min password length",
            "pwdHistoryLength": "Password history",
            "maxPwdAge": "Max password age",
            "minPwdAge": "Min password age",
            "lockoutThreshold": "Lockout threshold",
            "lockoutDuration": "Lockout duration",
            "pwdProperties": "Password properties",
        }
        for key, label in pp_labels.items():
            if key in pp:
                val = pp[key]
                if isinstance(val, list):
                    val = val[0] if val else ""
                print(f"    {label:25s}: {val}")

    if result.get("custom_filter"):
        print(f"\n  [CUSTOM FILTER] ({len(result['custom_filter'])} hasil)")
        for item in result["custom_filter"][:10]:
            dn = item.get("dn", "")
            print(f"    - {dn}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="LDAP Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s --target 192.168.1.10
  %(prog)s --target dc.example.com --username admin --password P@ssw0rd
  %(prog)s --target dc.example.com --ssl
  %(prog)s --target dc.example.com --base "DC=example,DC=com"
  %(prog)s --target dc.example.com --filter "(objectClass=user)"
        """,
    )
    parser.add_argument("--target", "-t", required=True, help="Target LDAP server (IP/hostname)")
    parser.add_argument("--port", "-p", type=int, help="Port LDAP (default: 389, atau 636 dengan --ssl)")
    parser.add_argument("--username", "-u", help="Username untuk authenticated bind")
    parser.add_argument("--password", "-P", help="Password untuk authenticated bind")
    parser.add_argument("--base", "-b", help="Base DN (default: auto-detect)")
    parser.add_argument("--filter", "-f", help="Custom LDAP filter (e.g. (objectClass=user))")
    parser.add_argument("--ssl", action="store_true", help="Gunakan LDAPS (port 636)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout koneksi (default: 10s)")
    args = parser.parse_args()

    if HAS_LDAP:
        log_info("Menggunakan python-ldap untuk enumerasi")
        result = scan_python_ldap(args)
    else:
        log_warn("python-ldap tidak tersedia. Menggunakan raw socket (kemampuan terbatas).")
        log_info("Install python-ldap: pip install python-ldap")
        result = scan_raw_socket(args)

    display_results(result)


if __name__ == "__main__":
    main()
