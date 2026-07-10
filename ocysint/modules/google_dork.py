"""Google Dork generator (tanpa scraping - hanya generate dork siap pakai)."""

from typing import Any, Dict, List

DORKS: Dict[str, List[Dict[str, str]]] = {
    "Files Exposed (filetype)": [
        {"name": "PDF di domain target", "dork": "site:{target} filetype:pdf"},
        {"name": "DOC/DOCX Exposed", "dork": "site:{target} (filetype:doc OR filetype:docx)"},
        {
            "name": "XLS Exposed",
            "dork": "site:{target} (filetype:xls OR filetype:xlsx OR filetype:csv)",
        },
        {
            "name": "Log Files Exposed",
            "dork": "site:{target} (filetype:log OR filetype:sql OR filetype:env)",
        },
        {
            "name": "Backup file",
            "dork": "site:{target} (filetype:bak OR filetype:old OR filetype:backup)",
        },
        {
            "name": "File konfigurasi",
            "dork": "site:{target} (filetype:conf OR filetype:cfg OR filetype:ini)",
        },
    ],
    "Login/Admin Exposed": [
        {
            "name": "Halaman admin",
            "dork": "site:{target} inurl:admin OR inurl:login OR inurl:wp-admin",
        },
        {"name": "Login form", "dork": 'site:{target} intitle:"login" OR intitle:"sign in"'},
        {
            "name": "Panel admin",
            "dork": "site:{target} inurl:dashboard OR inurl:panel OR inurl:cpanel",
        },
    ],
    "Directory Exposed": [
        {"name": "Directory listing", "dork": 'site:{target} intitle:"index of"'},
        {"name": "Parent directory", "dork": 'site:{target} intitle:"parent directory"'},
        {"name": "Open folder", "dork": 'site:{target} intitle:"index of" "parent directory"'},
    ],
    "Data Exposed": [
        {"name": "Email Exposed", "dork": 'site:{target} "@{target}"'},
        {"name": "Password Exposed", "dork": 'site:{target} "password" filetype:txt'},
        {
            "name": "API Key Exposed",
            "dork": 'site:{target} "api_key" OR "apikey" OR "access_token"',
        },
        {
            "name": "Database Exposed",
            "dork": "site:{target} inurl:db OR inurl:database OR inurl:phpmyadmin",
        },
    ],
    "Error/Debug Exposed": [
        {"name": "SQL error", "dork": 'site:{target} "SQL syntax" OR "mysql_fetch" OR "ORA-"'},
        {"name": "PHP error", "dork": 'site:{target} "Fatal error" OR "Warning:" "php"'},
        {"name": "Debug mode", "dork": 'site:{target} "DEBUG" OR "stacktrace" OR "traceback"'},
    ],
    "Tech Stack Detection": [
        {"name": "WordPress", "dork": "site:{target} inurl:wp-content OR inurl:wp-includes"},
        {"name": "Joomla", "dork": "site:{target} inurl:joomla OR inurl:option=com_"},
        {
            "name": "PHP framework",
            "dork": "site:{target} inurl:laravel OR inurl:symfony OR inurl:yii",
        },
        {
            "name": "Server header",
            "dork": 'site:{target} inurl:"server-status" OR inurl:"server-info"',
        },
    ],
}


def generate_dorks(target: str, category: str = "all") -> List[Dict[str, str]]:
    """Hasilkan dork list siap pakai untuk {target}."""
    target = target.strip()
    cats = list(DORKS.keys()) if category == "all" else [category]
    out: List[Dict[str, str]] = []
    for c in cats:
        if c not in DORKS:
            continue
        for d in DORKS[c]:
            out.append(
                {
                    "category": c,
                    "name": d["name"],
                    "dork": d["dork"].format(target=target),
                }
            )
    return out


def to_browser_url(dork: str) -> str:
    from urllib.parse import quote_plus

    return f"https://www.google.com/search?q={quote_plus(dork)}"


def list_categories() -> List[str]:
    return list(DORKS.keys())
