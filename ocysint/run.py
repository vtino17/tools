#!/usr/bin/env python3
"""OCySec OSINT Framework - CLI entry point. Authorized Pentest Use Only."""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

from core.banner import err, info, ok, print_banner, warn
from core.config import get_api_key, load_config, save_config
from modules.breach_check import run_breach_check
from modules.domain_recon import run_domain_recon
from modules.email_recon import run_email_recon
from modules.google_dork import generate_dorks, to_browser_url
from modules.leak_check import run_leak_check
from modules.metadata import extract_metadata
from modules.phone_recon import run_phone_recon
from modules.shodan_recon import run_shodan_recon
from modules.username_recon import filter_found, run_username_recon
from reports.generator import save_report



def cmd_email(args):
    info(f"Recon email: {args.email}")
    out = run_email_recon(args.email, get_api_key("hibp") or "")
    print(f"  - format valid    : {out.get('valid_format')}")
    print(f"  - domain          : {out.get('domain')}")
    print(f"  - MX records      : {len(out.get('mx_records', []))}")
    print(f"  - mail provider   : {out.get('mail_provider')}")
    print(f"  - disposable      : {out.get('disposable')}")
    print(f"  - gravatar        : {out.get('gravatar', {}).get('exists')}")
    if args.breach:
        out["breach_check"] = run_breach_check(email=args.email)
    if args.leak:
        out["leak_check"] = run_leak_check(args.email)
    return out


def cmd_username(args):
    info(f"Recon username: {args.username}")
    results = run_username_recon(args.username, args.concurrency)
    found = filter_found(results)
    ok(f"Ditemukan di {len(found)} platform dari {len(results)} yang dicek")
    for r in found:
        print(f"  [+] {r['platform']:<22} {r['url']}")
    return {"username": args.username, "found": found, "all": results}


def cmd_phone(args):
    info(f"Recon phone: {args.phone}")
    out = run_phone_recon(args.phone)
    print(f"  - normalized     : {out.get('normalized')}")
    print(f"  - country code   : {out.get('country_code')}")
    print(f"  - country hint   : {out.get('country_hint')}")
    print(f"  - valid length   : {out.get('is_valid_length')}")
    nv = out.get("numverify", {})
    if not nv.get("skipped"):
        print(f"  - numverify      : valid={nv.get('valid')} carrier={nv.get('carrier')}")
    else:
        warn("Numverify dilewati - API key belum diset")
    return out


def cmd_domain(args):
    info(f"Recon domain: {args.domain}")
    out = run_domain_recon(args.domain, do_subdomain=not args.no_subdomain)
    print(f"  - IPs            : {len(out.get('ips', []))}")
    for ip in out.get("ips", []):
        print(f"      {ip}")
    dns = out.get("dns", {})
    for t in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        v = dns.get(t, [])
        if v:
            print(f"  - DNS {t:<6} : {len(v)} records")
    sub = out.get("subdomains", [])
    if sub:
        print(f"  - subdomains     : {len(sub)}")
        for s in sub[:20]:
            print(f"      {s}")
        if len(sub) > 20:
            print(f"      ... and {len(sub) - 20} more")
    if args.shodan and out.get("ips"):
        out["shodan"] = run_shodan_recon(out["ips"][0], "ip")
    return out


def cmd_ip(args):
    info(f"Recon IP: {args.ip}")
    out = run_shodan_recon(args.ip, "ip")
    if not out.get("sources"):
        warn("Tidak ada Shodan/Censys API key")
    return out


def cmd_file(args):
    info(f"Extract metadata: {args.file}")
    out = extract_metadata(args.file)
    h = out.get("hashes", {})
    print(f"  - md5            : {h.get('md5')}")
    print(f"  - sha1           : {h.get('sha1')}")
    print(f"  - sha256         : {h.get('sha256')}")
    if out.get("exif"):
        cam = out["exif"].get("Make", "?")
        model = out["exif"].get("Model", "?")
        print(f"  - kamera         : {cam} {model}")
    if out.get("gps"):
        print(f"  - GPS            : {out['gps']}")
    if out.get("core_xml"):
        print(f"  - DOCX core.xml  : ada")
    return out


def cmd_dork(args):
    info(f"Generate Google Dorks: {args.dork}")
    dorks = generate_dorks(args.dork, args.category)
    for d in dorks:
        url = to_browser_url(d["dork"])
        print(f"  [{d['category']}] {d['name']}")
        print(f"    dork: {d['dork']}")
        print(f"    url : {url}")
    return {"target": args.dork, "dorks": dorks}


def cmd_password(args):
    info("Cek password (via HIBP k-anonymity)")
    out = run_breach_check(password=args.password)
    pc = out.get("password_check", {})
    if pc.get("pwned"):
        err(f"PASSWORD BOCOR! Muncul di {pc.get('count'):,} breach.")
    elif pc.get("error"):
        warn(f"Error: {pc['error']}")
    else:
        ok("Password TIDAK ditemukan di database HIBP.")
    return out


def cmd_all(args):
    out = {"target": args.target}
    target = args.target
    if "@" in target:
        out["email"] = cmd_email(argparse.Namespace(email=target, breach=True, leak=True))
    if target.replace("+", "").replace("-", "").isdigit():
        out["phone"] = cmd_phone(argparse.Namespace(phone=target))
    if "." in target and "@" not in target and not target.replace("+", "").replace("-", "").isdigit():
        out["domain"] = cmd_domain(argparse.Namespace(domain=target, no_subdomain=False, shodan=True))
    out["username"] = cmd_username(argparse.Namespace(username=target, concurrency=20))
    return out


def cmd_config(args):
    cfg = load_config()
    if args.config_action == "list":
        for k, v in cfg.get("api_keys", {}).items():
            masked = ("*" * 8 + v[-4:]) if v else "(kosong)"
            print(f"  {k:<15} : {masked}")
        return cfg
    if args.config_action == "set":
        cfg["api_keys"][args.key] = args.value
        save_config(cfg)
        ok(f"API key {args.key} disimpan")
        return cfg
    if args.config_action == "unset":
        if args.key in cfg["api_keys"]:
            cfg["api_keys"][args.key] = ""
            save_config(cfg)
            ok(f"API key {args.key} dihapus")
        return cfg
    return cfg


def maybe_save(args, data, target):
    if not (args.report or args.output) or args.no_report:
        return
    out_dir = args.output if args.output else str(ROOT / "reports")
    formats = ["json", "txt", "html"] if args.report == "all" else [args.report]
    written = save_report(out_dir, target, data, formats)
    ok("Laporan disimpan:")
    for fmt, p in written.items():
        print(f"  - {fmt}: {p}")



def build_parser():
    p = argparse.ArgumentParser(prog="ocysint", description="OCySec OSINT Framework - Authorized Pentest Use Only")
    p.add_argument("--report", choices=["json", "txt", "html", "all"], help="Generate report")
    p.add_argument("--output", help="Output directory untuk report")
    p.add_argument("--no-report", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    pe = sub.add_parser("email", help="Email reconnaissance")
    pe.add_argument("email")
    pe.add_argument("--breach", action="store_true", help="Cek HIBP breach")
    pe.add_argument("--leak", action="store_true", help="Cek DeHashed/IntelX")
    pe.set_defaults(func=cmd_email)

    pu = sub.add_parser("username", help="Username enumeration 50+ platform")
    pu.add_argument("username")
    pu.add_argument("-c", "--concurrency", type=int, default=20)
    pu.set_defaults(func=cmd_username)

    pp = sub.add_parser("phone", help="Phone number lookup")
    pp.add_argument("phone")
    pp.set_defaults(func=cmd_phone)

    pd = sub.add_parser("domain", help="Domain recon (WHOIS/DNS/Sub/SSL)")
    pd.add_argument("domain")
    pd.add_argument("--no-subdomain", action="store_true")
    pd.add_argument("--shodan", action="store_true")
    pd.set_defaults(func=cmd_domain)

    pi = sub.add_parser("ip", help="IP recon (Shodan/Censys)")
    pi.add_argument("ip")
    pi.set_defaults(func=cmd_ip)

    pf = sub.add_parser("file", help="Extract metadata file")
    pf.add_argument("file")
    pf.set_defaults(func=cmd_file)

    pdk = sub.add_parser("dork", help="Generate Google Dorks")
    pdk.add_argument("dork")
    pdk.add_argument("--category", default="all")
    pdk.set_defaults(func=cmd_dork)

    ppw = sub.add_parser("password", help="Cek password breach (k-anonymity)")
    ppw.add_argument("password")
    ppw.set_defaults(func=cmd_password)

    pa = sub.add_parser("all", help="Auto-detect & jalankan semua modul relevan")
    pa.add_argument("target")
    pa.set_defaults(func=cmd_all)

    pc = sub.add_parser("config", help="Kelola API key & config")
    pcsub = pc.add_subparsers(dest="config_action")
    pcsub.add_parser("list")
    pcset = pcsub.add_parser("set")
    pcset.add_argument("key")
    pcset.add_argument("value")
    pcunset = pcsub.add_parser("unset")
    pcunset.add_argument("key")
    pc.set_defaults(func=cmd_config)

    return p


def main():
    print_banner()
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    target_label = (getattr(args, "email", None) or getattr(args, "username", None)
                    or getattr(args, "phone", None) or getattr(args, "domain", None)
                    or getattr(args, "ip", None) or getattr(args, "file", None)
                    or getattr(args, "dork", None) or getattr(args, "password", None)
                    or getattr(args, "target", None) or "config")

    try:
        result = args.func(args)
    except KeyboardInterrupt:
        err("Dibatalkan user.")
        return 130
    except Exception as e:
        err(f"Error: {e}")
        import traceback
        if os.environ.get("OCYSINT_DEBUG"):
            traceback.print_exc()
        return 1

    if isinstance(result, dict) and result and target_label != "config":
        maybe_save(args, result, str(target_label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
