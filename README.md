#!/usr/bin/env python3
# -- coding: utf-8 --
# sait_scan_final.py
# SaitScan — Full Passive Checker (final)
# - ASCII banner center-aligned
# - Loader animation while checks run
# - Only green/red colors in output
# - Admin/login detection prints full URL(s) clearly
# - Outputs directly to terminal (no files). White-hat only. GET-only.

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests, ipaddress, sys, re, time

console = Console()

UA = {"User-Agent": "SaitScan-Final/2025"}
TIMEOUT = 8
COMMON_SENSITIVE = [".env", ".git/HEAD", "wp-config.php", ".htpasswd", ".git/config"]
COMMON_ADMIN_PATHS = ["/admin", "/admin/login", "/administrator", "/administrator/login",
                      "/wp-admin", "/wp-login.php", "/manager/html", "/login", "/user/login",
                      "/users/sign_in", "/dashboard", "/cpanel"]
COMMON_DIRS = ["/", "/uploads/", "/static/", "/files/", "/backup/", "/backups/"]
MAX_WORKERS = 8

def looks_like_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except:
        return False

def norm_url(u):
    u = u.strip()
    if not u:
        return ""
    if not re.match(r"^https?://", u):
        host = u.split("/")[0]
        if looks_like_ip(host):
            return "http://" + u
        else:
            return "https://" + u
    return u

def safe_get(url):
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT, allow_redirects=True)
        return r
    except Exception as e:
        return {"error": str(e)}

def check_security_headers(resp):
    keys = ["Strict-Transport-Security","Content-Security-Policy",
            "X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"]
    hdrs = {}
    for k in keys:
        val = resp.headers.get(k)
        hdrs[k] = val
    return hdrs

def check_sensitive(base):
    found = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(safe_get, urljoin(base, p)): p for p in COMMON_SENSITIVE}
        for fut in as_completed(futs):
            res = fut.result()
            p = futs[fut]
            if isinstance(res, dict) and res.get("error"):
                continue
            sc = getattr(res, "status_code", None)
            if sc == 200:
                snippet = (res.text or "")[:200].replace('<','&lt;').replace('>','&gt;')
                found.append({"path": p, "status": sc, "snippet": snippet})
            elif sc in (401,403):
                found.append({"path": p, "status": sc, "snippet": ""})
    return found

def check_admins(base):
    found = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(safe_get, urljoin(base, p)): p for p in COMMON_ADMIN_PATHS}
        for fut in as_completed(futs):
            res = fut.result()
            p = futs[fut]
            if isinstance(res, dict) and res.get("error"):
                continue
            sc = getattr(res, "status_code", None)
            if sc == 200:
                html = res.text or ""
                has_pass = ("type=\"password\"" in html.lower()) or ("name=\"password\"" in html.lower())
                m = re.search(r"<title[^>]>(.?)</title>", html, re.I|re.S)
                title = m.group(1).strip() if m else ""
                found.append({"path": p, "status": sc, "has_password_field": bool(has_pass), "title": title})
    return found

def check_dir_listing(base):
    dl = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(safe_get, urljoin(base, p)): p for p in COMMON_DIRS}
        for fut in as_completed(futs):
            res = fut.result()
            p = futs[fut]
            if isinstance(res, dict) and res.get("error"):
                continue
            html = getattr(res, "text", "") or ""
            if "index of /" in html.lower() or "parent directory" in html.lower():
                dl.append({"path": p, "status": getattr(res, "status_code", None)})
    return dl

def passive_reflection_tests(base, params):
    marker = "SAITSCAN_MARKER_2025"
    reflections = []
    for p in params[:40]:
        try:
            r = requests.get(base, params={p: marker}, headers=UA, timeout=TIMEOUT)
            if isinstance(r, dict):
                continue
            if marker in (r.text or ""):
                reflections.append({"param": p, "tested_url": r.url, "status": r.status_code})
        except:
            continue
    return reflections

def sql_error_tests(base, params):
    payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
    findings = []
    for p in params[:30]:
        for pl in payloads:
            try:
                r = requests.get(base, params={p: pl}, headers=UA, timeout=TIMEOUT)
                txt = (r.text or "").lower()
                if any(x in txt for x in ["sql syntax", "mysql", "syntax error", "pdoexception", "sqlstate", "mysql_fetch"]):
                    findings.append({"param": p, "payload": pl, "status": r.status_code})
            except:
                continue
    return findings

def extract_links_params(html):
    params = set()
    for m in re.finditer(r"[?&]([a-zA-Z0-9_\-]+)=", html):
        params.add(m.group(1))
    for m in re.finditer(r'<input[^>]+name=["\']?([a-zA-Z0-9_\-]+)', html, re.I):
        params.add(m.group(1))
    return list(params)[:200]

def compute_score(report):
    score = 0
    reasons = []
    sh = report.get("security_headers", {})
    if not sh.get("Strict-Transport-Security"):
        score += 12; reasons.append("No HSTS (+12)")
    if not sh.get("Content-Security-Policy"):
        score += 18; reasons.append("No CSP (+18)")
    sens = [s for s in report.get("sensitive_files", []) if s.get("status")==200]
    prot = [s for s in report.get("sensitive_files", []) if s.get("status") in (401,403)]
    score += min(30, len(sens)*10 + len(prot)*3)
    if sens: reasons.append(f"{len(sens)} exposed sensitive file(s)")
    if prot and not sens: reasons.append(f"{len(prot)} protected sensitive file(s) (403)")
    admins = report.get("admin_pages", [])
    if admins:
        score += min(20, len(admins)*8); reasons.append(f"{len(admins)} admin page(s) accessible")
    refl = report.get("reflection_tests", [])
    if refl:
        score += min(15, len(refl)*5); reasons.append(f"{len(refl)} reflected param(s)")
    sqls = report.get("sql_like_tests", [])
    if sqls:
        score += min(15, len(sqls)*5); reasons.append(f"{len(sqls)} SQL-like indicator(s)")
    dl = report.get("directory_listing_checks", [])
    if dl:
        score += 5; reasons.append("Directory listing detected (+5)")
    if score > 100: score = 100
    return int(score), reasons

def show_report(report):
    # Print header rule
    console.print(Rule(title="Khulasé", style="green"))
    # Overview
    t = Table.grid(expand=True)
    t.add_column(ratio=1)
    t.add_column(ratio=2)
    t.add_row("Target:", report.get("target"))
    t.add_row("Final URL:", report.get("final_url"))
    t.add_row("HTTP status:", str(report.get("http_status")))
    console.print(Panel(t, title="Overview", border_style="green"))

    # Risk score
    score, reasons = compute_score(report)
    score_text = f"[red]{score}%[/red]" if score>50 else f"[green]{score}%[/green]"
    console.print(Panel(f"Estimated chance a hacker can exploit: {score_text}\nReasons: {', '.join(reasons) if reasons else 'None'}", title="Risk Estimation", border_style="green"))

    # Security headers
    sh = report.get("security_headers", {})
    sec = Table(show_header=True)
    sec.add_column("Header")
    sec.add_column("Status")
    for k,v in sh.items():
        status = "[green]OK[/green]" if v else "[red]Missing[/red]"
        sec.add_row(k, status)
    console.print(Panel(sec, title="Security Headers (green=ok, red=missing)", border_style="green"))

    # Sensitive files
    sf = report.get("sensitive_files", [])
    if sf:
        st = Table(show_header=True)
        st.add_column("Path")
        st.add_column("Status")
        for s in sf:
            st.add_row(s.get("path"), "[red]200 (exposed)[/red]" if s.get("status")==200 else "[green]Protected (403/401)[/green]")
        console.print(Panel(st, title="Sensitive files", border_style="green"))
    else:
        console.print(Panel("[green]No common sensitive files found[/green]", border_style="green"))

    # Admin pages — table (kept) and then clear full-URLs section
    ap = report.get("admin_pages", [])
    if ap:
        at = Table(show_header=True)
        at.add_column("Path")
        at.add_column("Status")
        at.add_column("Has password field")
        at.add_column("Title (if any)")
        for a in ap:
            at.add_row(a.get("path"), "[red]200[/red]", "[green]Yes[/green]" if a.get("has_password_field") else "[red]No[/red]", a.get("title") or "")
        console.print(Panel(at, title="Admin/Login pages (red=problem)", border_style="green"))

        # Also print the full URL(s) clearly and prominently (only green/red colors)
        base = report.get("base") or ""
        console.print(Panel("[bold]Found admin/login page(s):[/bold]", border_style="green"))
        for a in ap:
            full = urljoin(base, a.get("path"))
            hint = "(has password field)" if a.get("has_password_field") else "(no password field in static HTML)"
            console.print(f"[green]{full}[/green] {hint} {('— ' + a.get('title')) if a.get('title') else ''}")
    else:
        console.print(Panel("[green]No common admin/login pages found[/green]", border_style="green"))

    # Reflections
    refl = report.get("reflection_tests", [])
    if refl:
        rt = Table(show_header=True)
        rt.add_column("Param")
        rt.add_column("Tested URL")
        for r in refl:
            rt.add_row(r.get("param"), r.get("tested_url"))
        console.print(Panel(rt, title="Reflected params (passive) — possible XSS", border_style="green"))
    else:
        console.print(Panel("[green]No passive reflections found[/green]", border_style="green"))

    # SQL-like indicators
    sqls = report.get("sql_like_tests", [])
    if sqls:
        st = Table(show_header=True)
        st.add_column("Param")
        st.add_column("Payload")
        for s in sqls:
            st.add_row(s.get("param"), s.get("payload"))
        console.print(Panel(st, title="SQL-like error indicators (heuristic)", border_style="green"))
    else:
        console.print(Panel("[green]No SQL error signatures detected[/green]", border_style="green"))

    # Directory listing
    dl = report.get("directory_listing_checks", [])
    if dl:
        dt = Table(show_header=True)
        dt.add_column("Path")
        dt.add_column("Status")
        for d in dl:
            dt.add_row(d.get("path"), "[red]dir listing[/red]")
        console.print(Panel(dt, title="Directory listing detected", border_style="green"))
    else:
        console.print(Panel("[green]No directory listing on common paths[/green]", border_style="green"))

    console.print(Panel("[bold]Only use with permission — this tool is passive (GET-only).[/bold]"))

def run_all_checks(normalized, params):
    parsed = urlparse(normalized)
    base = f"{parsed.scheme}://{parsed.netloc}"
    report = {"target": normalized, "final_url": normalized, "base": base}
    r = safe_get(normalized)
    if isinstance(r, dict) and r.get("error"):
        report["http_status"] = None
        report["security_headers"] = {}
        report["sensitive_files"] = []
        report["admin_pages"] = []
        report["directory_listing_checks"] = []
        report["reflection_tests"] = []
        report["sql_like_tests"] = []
        report["error"] = r.get("error")
        return report

    report["http_status"] = getattr(r, "status_code", None)
    report["security_headers"] = check_security_headers(r)
    # run parallel checks for files, admins, dirs
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        f1 = ex.submit(check_sensitive, base)
        f2 = ex.submit(check_admins, base)
        f3 = ex.submit(check_dir_listing, base)
        sensitive = f1.result()
        admins = f2.result()
        dls = f3.result()
    reflections = passive_reflection_tests(normalized, params)
    sqls = sql_error_tests(normalized, params)

    report["sensitive_files"] = sensitive
    report["admin_pages"] = admins
    report["directory_listing_checks"] = dls
    report["reflection_tests"] = reflections
    report["sql_like_tests"] = sqls
    return report

def main():
    console.clear()
    ascii_banner = r"""
   ╔═╗╔═╗╦╔╦╗   ╔═╗╔═╗╔═╗╔╗ ╔═╗
   ╚═╗║╣ ║ ║║───║-  ║ ║║ ║╠╩╗║╣ 
   ╚═╝╚═╝╩═╩╝   ╚═╝╚═╝╚═╝╚═╝╚═╝
        SaitScan — Full Passive Site Checker
               (White-hat use only)
    2025 © Mostafa.hk — https://t.me/Mo303067
"""
    console.print(ascii_banner, justify="center")

    target = Prompt.ask("Address ya IP (example.com ya 192.178.0.1)")
    if not target:
        console.print("[red]Address vared nashod. Exit.[/red]")
        sys.exit(0)
    normalized = norm_url(target)
    parsed = urlparse(normalized)
    base = f"{parsed.scheme}://{parsed.netloc}"
    console.print(f"Target normalized: [green]{base}[/green]")

    if not Confirm.ask("Are you the owner of the site? (y/n)"):
        console.print("[red]Canceled — need permission.[/red]")
        sys.exit(0)

    # initial fetch to extract params
    r = safe_get(normalized)
    if isinstance(r, dict) and r.get("error"):
        console.print(Panel(f"[red]Error connecting: {r.get('error')}[/red]"))
        sys.exit(0)
    html = getattr(r, "text", "") or ""
    params = extract_links_params(html)

    # run checks in background while showing loader
    with Progress(SpinnerColumn(), TextColumn("[bold]SCANNING...[/bold]")) as progress:
        task = progress.add_task("", total=None)
        # run checks in thread so spinner animates
        from threading import Thread
        result_holder = {}
        def worker():
            result_holder["report"] = run_all_checks(normalized, params)
        th = Thread(target=worker, daemon=True)
        th.start()
        while th.is_alive():
            time.sleep(0.1)
        progress.remove_task(task)

    report = result_holder.get("report", {})
    show_report(report)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
        sys.exit(0)
