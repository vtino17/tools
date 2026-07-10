"""
HackerAI Report Generator
Export hasil scan/analisis ke HTML, JSON, atau Markdown.
"""

import json
import os
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path(__file__).resolve().parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)


def generate_html_report(
    title: str,
    sections: list,
    filename: str = None,
    output_dir: str = None,
) -> str:
    """Generate laporan HTML dari list of sections.

    Args:
        title: Judul laporan
        sections: List of dicts [{"heading": ..., "content": ..., "type": "text|table|list"}]
        filename: Nama file (auto jika None)
        output_dir: Output directory (default: reports/)

    Returns:
        Path ke file HTML yang dihasilkan
    """
    dir_path = Path(output_dir) if output_dir else REPORT_DIR
    dir_path.mkdir(parents=True, exist_ok=True)

    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = title.lower().replace(" ", "_")[:30]
        filename = f"report_{safe_title}_{ts}.html"

    html_rows = []
    for sec in sections:
        heading = sec.get("heading", "")
        html_rows.append(f"<h2>{heading}</h2>")
        stype = sec.get("type", "text")
        content = sec.get("content", "")
        if stype == "table" and isinstance(content, list):
            if content:
                headers = content[0].keys()
                html_rows.append(
                    "<table border='1' cellpadding='6' style='border-collapse:collapse'>"
                )
                html_rows.append("<tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>")
                for row in content:
                    html_rows.append(
                        "<tr>" + "".join(f"<td>{row.get(h, '')}</td>" for h in headers) + "</tr>"
                    )
                html_rows.append("</table>")
        elif stype == "list" and isinstance(content, list):
            html_rows.append("<ul>")
            for item in content:
                html_rows.append(f"<li>{item}</li>")
            html_rows.append("</ul>")
        else:
            html_rows.append(f"<pre>{content}</pre>" if "\n" in content else f"<p>{content}</p>")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; max-width: 960px; margin: 30px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }}
        h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
        h2 {{ color: #f0f6fc; margin-top: 30px; }}
        table {{ width: 100%; background: #161b22; }}
        th {{ background: #21262d; color: #58a6ff; }}
        td, th {{ padding: 8px 12px; text-align: left; }}
        pre {{ background: #161b22; padding: 15px; border-radius: 6px; overflow-x: auto; }}
        .meta {{ color: #8b949e; font-size: 0.9em; }}
        ul {{ line-height: 1.6; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    {''.join(html_rows)}
</body>
</html>"""

    path = dir_path / filename
    path.write_text(html, encoding="utf-8")
    return str(path)


def generate_json_report(data: dict, filename: str = None, output_dir: str = None) -> str:
    """Export data sebagai JSON report."""
    dir_path = Path(output_dir) if output_dir else REPORT_DIR
    dir_path.mkdir(parents=True, exist_ok=True)

    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{ts}.json"

    report = {
        "generated_at": datetime.now().isoformat(),
        "data": data,
    }

    path = dir_path / filename
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return str(path)


def generate_markdown_report(
    title: str,
    sections: list,
    filename: str = None,
    output_dir: str = None,
) -> str:
    """Generate laporan Markdown."""
    dir_path = Path(output_dir) if output_dir else REPORT_DIR
    dir_path.mkdir(parents=True, exist_ok=True)

    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = title.lower().replace(" ", "_")[:30]
        filename = f"report_{safe_title}_{ts}.md"

    lines = [f"# {title}\n", f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"]

    for sec in sections:
        heading = sec.get("heading", "")
        lines.append(f"## {heading}\n")
        stype = sec.get("type", "text")
        content = sec.get("content", "")
        if stype == "table" and isinstance(content, list) and content:
            headers = list(content[0].keys())
            sep = "| " + " | ".join("---" for _ in headers) + " |"
            hdr = "| " + " | ".join(headers) + " |"
            lines.append(hdr)
            lines.append(sep)
            for row in content:
                vals = [str(row.get(h, "")).replace("\n", " ") for h in headers]
                lines.append("| " + " | ".join(vals) + " |")
            lines.append("")
        elif stype == "list" and isinstance(content, list):
            for item in content:
                lines.append(f"- {item}")
            lines.append("")
        else:
            lines.append(f"{content}\n")

    path = dir_path / filename
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)
