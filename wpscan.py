#!/usr/bin/env python3
"""
wp_full_audit.py

Comprehensive passive WordPress security auditor + vulnerability lookup.

Added WPScan capabilities:
- Run local WPScan CLI (--use-wpscan-cli)
- Use WPScan API (--wpscan-key) to lookup wordpresses/plugins/themes
- WPScan results are stored under audit["vuln_data"]["wpscan_cli"] and audit["vuln_data"]["wpscan_api"]

Updated: Saves reports in structured folders per target.
"""

from __future__ import annotations
import argparse
import json
import re
import sys
import time
import html
import shutil
import subprocess
import os
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# ==============================
# Configuration / Defaults
# ==============================
USER_AGENT = "WP-Full-Audit/1.0 (+https://yourdomain.example)"
REQUEST_TIMEOUT = 12
SLEEP_BETWEEN_REQUESTS = 0.8
MAX_PLUGIN_PROBES = 120
ENABLE_VERBOSE = False

WPSCAN_API_BASE = "https://wpscan.com/api/v3"  # WPScan API base
WPSCAN_CLI_BINARY = shutil.which("wpscan")    # None if not installed

# Default plugin paths to probe (conservative)
COMMON_PLUGIN_PROBES = [
    "wp-content/plugins/akismet/readme.txt",
    "wp-content/plugins/jetpack/readme.txt",
    "wp-content/plugins/woocommerce/readme.txt",
    "wp-content/plugins/contact-form-7/readme.txt",
    "wp-content/plugins/elementor/readme.txt",
    "wp-content/plugins/wpforms-lite/readme.txt",
    "wp-content/plugins/wordfence/readme.txt",
    "wp-content/plugins/duplicator/readme.txt",
    "wp-content/plugins/updraftplus/readme.txt",
    "wp-content/plugins/all-in-one-wp-migration/readme.txt",
    "wp-content/plugins/slider-revolution/readme.txt",
    "wp-content/plugins/rtmedia/readme.txt",
    "wp-content/plugins/revslider/readme.txt",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Content-Type-Options",
]

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/1.0"

# ==============================
# HTTP session
# ==============================
def make_session(timeout=REQUEST_TIMEOUT):
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    retries = Retry(total=2, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    return s

session = make_session()

# ==============================
# Helpers
# ==============================
def norm_url(u: str) -> str:
    u = u.strip()
    if not u:
        raise ValueError("Empty URL")
    if not urlparse(u).scheme:
        u = "http://" + u
    return u.rstrip("/")

def safe_get(url: str, allow_redirects=True, raise_on_5xx=False):
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects, verify=True)
        if raise_on_5xx and r.status_code >= 500:
            raise requests.HTTPError(f"HTTP {r.status_code}")
        return r
    except requests.exceptions.SSLError:
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects, verify=False)
            return r
        except Exception:
            return None
    except Exception:
        return None

def short(t: float) -> str:
    return datetime.utcfromtimestamp(t).isoformat() + "Z"

# ==============================
# Passive checks
# ==============================
def detect_wordpress(resp):
    evidence = []
    if not resp:
        return False, evidence
    body = resp.text or ""
    headers = resp.headers or {}
    patterns = [r"wp-content", r"wp-includes", r"wp-emoji-release", r"wp-xmlrpc.php", r"wp-login.php"]
    for p in patterns:
        if re.search(p, body, re.I):
            evidence.append(f"html_pattern:{p}")
    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body, re.I)
    if m and "WordPress" in m.group(1):
        evidence.append(f"meta_generator:{m.group(1)}")
    for k, v in headers.items():
        if "x-powered-by" in k.lower() and v and "php" in v.lower():
            evidence.append(f"header:{k}:{v}")
    return len(evidence) > 0, evidence

def detect_wp_version(resp, base_url):
    findings = {"meta": None, "readme": None, "theme_style": None}
    if resp:
        m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d\.]+)?["\']', resp.text or "", re.I)
        if m:
            findings["meta"] = m.group(1) if m.group(1) else "unknown"
    readme_url = urljoin(base_url + "/", "readme.html")
    r2 = safe_get(readme_url)
    if r2 and r2.status_code == 200 and "wordpress" in (r2.text or "").lower():
        mm = re.search(r"Version\s*([\d\.]+)", r2.text, re.I)
        findings["readme"] = mm.group(1) if mm else "present"
    if resp:
        m = re.search(r'href=["\']([^"\']+?/wp-content/themes/[^/]+/style.css)["\']', resp.text or "", re.I)
        if m:
            style_url = urljoin(base_url + "/", m.group(1))
            r3 = safe_get(style_url)
            if r3 and r3.status_code == 200:
                mm = re.search(r"Version:\s*([\d\.]+)", r3.text, re.I)
                findings["theme_style"] = mm.group(1) if mm else "present"
    return findings

def check_https_and_hsts(base_url):
    res = {"https": False, "https_redirect": False, "hsts": False, "hsts_header": None}
    try:
        http_url = re.sub(r"^https?://", "http://", base_url)
        https_url = re.sub(r"^https?://", "https://", base_url)
        r_http = safe_get(http_url)
        r_https = safe_get(https_url)
        if r_https and r_https.status_code < 400:
            res["https"] = True
        if r_http and hasattr(r_http, "is_redirect") and r_http.is_redirect:
            loc = r_http.headers.get("location", "")
            if loc and loc.startswith("https"):
                res["https_redirect"] = True
        if r_https:
            h = r_https.headers.get("Strict-Transport-Security")
            if h:
                res["hsts"] = True
                res["hsts_header"] = h
    except Exception:
        pass
    return res

def check_security_headers(resp):
    found = {}
    if not resp:
        return found
    for h in SECURITY_HEADERS:
        v = resp.headers.get(h)
        if v:
            found[h] = v
    if resp.headers.get("Server"):
        found["Server"] = resp.headers.get("Server")
    if resp.headers.get("X-Powered-By"):
        found["X-Powered-By"] = resp.headers.get("X-Powered-By")
    return found

def check_xmlrpc(base_url):
    url = urljoin(base_url + "/", "xmlrpc.php")
    r = safe_get(url)
    if not r:
        return {"accessible": False, "status": None}
    accessible = r.status_code in (200, 405) or ("XML-RPC server accepts POST requests" in (r.text or ""))
    return {"accessible": accessible, "status": r.status_code}

def check_rest_api_users(base_url):
    target = urljoin(base_url + "/", "wp-json/wp/v2/users")
    r = safe_get(target)
    if not r:
        return {"exposed": False, "status": None, "users": []}
    if r.status_code == 200:
        try:
            js = r.json()
            users = []
            if isinstance(js, list):
                for u in js:
                    users.append({"id": u.get("id"), "name": u.get("name"), "slug": u.get("slug")})
            return {"exposed": True, "status": 200, "users": users}
        except Exception:
            return {"exposed": True, "status": r.status_code, "users": []}
    return {"exposed": False, "status": r.status_code, "users": []}

def check_author_enumeration(base_url):
    url = base_url.rstrip("/") + "/?author=1"
    r = safe_get(url, allow_redirects=True)
    if not r:
        return {"enumerable": False, "status": None, "username": None}
    final = r.url
    m = re.search(r"/author/([^/?#]+)", final)
    if m:
        return {"enumerable": True, "status": r.status_code, "username": m.group(1), "final_url": final}
    m2 = re.search(r'author/(?:archives/)?([^"\'/?]+)', (r.text or ""), re.I)
    if m2:
        return {"enumerable": True, "status": r.status_code, "username": m2.group(1), "final_url": final}
    return {"enumerable": False, "status": r.status_code, "username": None}

def check_directory_listing(base_url):
    findings = {}
    common_dirs = ["wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/"]
    for d in common_dirs:
        url = urljoin(base_url + "/", d)
        r = safe_get(url)
        if r and r.status_code == 200:
            body = (r.text or "")
            if re.search(r"Index of /|Directory listing for|<title>Index of", body, re.I):
                findings[d] = True
            else:
                findings[d] = False
        elif r and r.status_code in (401, 403):
            findings[d] = "protected"
        else:
            findings[d] = False
    return findings

def probe_plugins(base_url, plugin_probes=None):
    if plugin_probes is None:
        plugin_probes = COMMON_PLUGIN_PROBES
    found = []
    counter = 0
    for probe in plugin_probes:
        if counter >= MAX_PLUGIN_PROBES:
            break
        url = urljoin(base_url + "/", probe)
        r = safe_get(url)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        counter += 1
        if r and r.status_code == 200 and len((r.text or "")) > 30:
            found.append({"path": probe, "url": url, "status": r.status_code})
    return found

def check_registration_enabled(base_url):
    url = urljoin(base_url + "/", "wp-login.php?action=register")
    r = safe_get(url, allow_redirects=True)
    if not r:
        return {"registration_enabled": False, "status": None}
    if "registration=disabled" in r.url or "User registration is currently not allowed" in (r.text or ""):
        return {"registration_enabled": False, "status": r.status_code}
    if re.search(r"name=[\"']user_login|name=[\"']user_email", r.text or "", re.I):
        return {"registration_enabled": True, "status": r.status_code}
    return {"registration_enabled": False, "status": r.status_code}

def check_wp_login_presence(base_url):
    url = urljoin(base_url + "/", "wp-login.php")
    r = safe_get(url, allow_redirects=True)
    if not r:
        return {"exists": False, "status": None}
    exists = False
    if r.status_code == 200 and re.search(r'name=["\']log["\']|name=["\']user_login["\']', r.text or "", re.I):
        exists = True
    return {"exists": exists, "status": r.status_code, "url": getattr(r, "url", None)}

def detect_cloudflare(resp):
    if not resp:
        return False
    server = resp.headers.get("Server", "") or ""
    cf_ray = resp.headers.get("CF-Ray")
    if "cloudflare" in server.lower() or cf_ray:
        return True
    return False

def detect_backup_plugins(resp_body):
    plugins = []
    body = resp_body or ""
    if "updraft" in body.lower():
        plugins.append("updraftplus")
    if "duplicator" in body.lower():
        plugins.append("duplicator")
    if "backwpup" in body.lower():
        plugins.append("backwpup")
    return list(set(plugins))

# ==============================
# Vulnerability DB helpers (WPScan & NVD)
# ==============================
def query_wpscan_wordpress(base_url, wpscan_token):
    if not wpscan_token:
        return None
    headers = {"Authorization": f"Token token={wpscan_token}", "User-Agent": USER_AGENT}
    try:
        r = requests.get(f"{WPSCAN_API_BASE}/wordpresses.json?url={base_url}", headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return {"error": f"wpscan_status_{r.status_code}", "body": r.text}
    except Exception as e:
        return {"error": str(e)}

def query_wpscan_plugin(plugin_slug, wpscan_token):
    if not wpscan_token:
        return None
    headers = {"Authorization": f"Token token={wpscan_token}", "User-Agent": USER_AGENT}
    try:
        r = requests.get(f"{WPSCAN_API_BASE}/plugins/{plugin_slug}.json", headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return {"error": f"wpscan_plugin_status_{r.status_code}", "body": r.text}
    except Exception as e:
        return {"error": str(e)}

def query_wpscan_theme(theme_slug, wpscan_token):
    if not wpscan_token:
        return None
    headers = {"Authorization": f"Token token={wpscan_token}", "User-Agent": USER_AGENT}
    try:
        r = requests.get(f"{WPSCAN_API_BASE}/themes/{theme_slug}.json", headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return {"error": f"wpscan_theme_status_{r.status_code}", "body": r.text}
    except Exception as e:
        return {"error": str(e)}

def run_wpscan_cli(target_url, api_token=None):
    if not WPSCAN_CLI_BINARY:
        return {"error": "wpscan_cli_not_found"}
    cmd = [WPSCAN_CLI_BINARY, "--url", target_url, "--no-update", "--format", "json"]
    if api_token:
        cmd.extend(["--api-token", api_token])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            return {"error": "wpscan_cli_failed", "stderr": p.stderr.strip(), "stdout": p.stdout.strip()}
        try:
            return json.loads(p.stdout)
        except Exception as e:
            return {"error": "wpscan_cli_parse_failed", "detail": str(e), "raw": p.stdout.strip()}
    except Exception as e:
        return {"error": str(e)}

def nvd_search(keyword, results_limit=5):
    try:
        params = {"keyword": keyword, "resultsPerPage": results_limit}
        r = session.get(NVD_API_BASE, params=params, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return {"error": f"nvd_status_{r.status_code}", "body": r.text}
    except Exception as e:
        return {"error": str(e)}

# ==============================
# Scoring & Recommendations
# ==============================
def compute_score(findings):
    score = 0
    if not findings.get("https", {}).get("https", False):
        score += 20
    if not findings.get("https", {}).get("hsts", False):
        score += 5
    headers = findings.get("security_headers", {})
    missing_headers = [h for h in SECURITY_HEADERS if h not in headers]
    score += min(20, len(missing_headers) * 3)
    if findings.get("xmlrpc", {}).get("accessible"):
        score += 10
    if findings.get("rest_api_users", {}).get("exposed"):
        score += 10
    if findings.get("author_enumeration", {}).get("enumerable"):
        score += 8
    if findings.get("directory_listing"):
        if any(v is True for v in findings["directory_listing"].values()):
            score += 10
    if findings.get("plugin_probes"):
        score += min(15, len(findings["plugin_probes"]))
    score = min(100, score)
    return score

def build_recommendations(findings):
    recs = []
    if not findings.get("https", {}).get("https", False):
        recs.append("Enable HTTPS and configure redirects to HTTPS.")
    if not findings.get("https", {}).get("hsts", False):
        recs.append("Consider enabling HSTS (Strict-Transport-Security).")
    headers = findings.get("security_headers", {})
    if "Content-Security-Policy" not in headers:
        recs.append("Add a Content-Security-Policy (start in report-only mode to avoid breaking site).")
    if findings.get("xmlrpc", {}).get("accessible"):
        recs.append("Disable or protect xmlrpc.php if not needed (block or rate-limit).")
    if findings.get("rest_api_users", {}).get("exposed"):
        recs.append("Restrict REST API user endpoints or use plugins to disable user listing.")
    if findings.get("author_enumeration", {}).get("enumerable"):
        recs.append("Fix author enumeration (remove user slugs from author archives).")
    if findings.get("directory_listing") and any(v is True for v in findings["directory_listing"].values()):
        recs.append("Disable directory indexing (Options -Indexes or autoindex off).")
    if findings.get("plugin_probes"):
        recs.append("Review installed plugins for outdated/vulnerable versions and remove unused plugins.")
    if findings.get("uploads_php_exec"):
        recs.append("Prevent PHP execution in the uploads directory (deny .php execution).")
    if not recs:
        recs.append("No urgent public issues found; continue with regular update/patching schedule.")
    return recs

# ==============================
# Audit orchestration
# ==============================
def audit_site(target_url, wpscan_key=None, use_wpscan_cli=False, patchstack_key=None, verbose=False):
    target_url = norm_url(target_url)
    audit = {
        "target": target_url,
        "timestamp": short(time.time()),
        "notes": "Passive scan only. No brute-force or authenticated checks performed.",
        "checks": {}
    }

    if verbose:
        print(f"[+] Fetching main page: {target_url}")
    resp = safe_get(target_url)
    time.sleep(SLEEP_BETWEEN_REQUESTS)

    # detection
    is_wp, evidence = detect_wordpress(resp)
    audit["checks"]["is_wordpress"] = is_wp
    audit["checks"]["evidence"] = evidence

    # https / hsts
    audit["checks"]["https"] = check_https_and_hsts(target_url)

    # headers
    audit["checks"]["security_headers"] = check_security_headers(resp)

    # version detection
    audit["checks"]["version_detection"] = detect_wp_version(resp, target_url)

    # xmlrpc
    audit["checks"]["xmlrpc"] = check_xmlrpc(target_url)
    time.sleep(SLEEP_BETWEEN_REQUESTS)

    # rest api users
    audit["checks"]["rest_api_users"] = check_rest_api_users(target_url)
    time.sleep(SLEEP_BETWEEN_REQUESTS)

    # author enum
    audit["checks"]["author_enumeration"] = check_author_enumeration(target_url)
    time.sleep(SLEEP_BETWEEN_REQUESTS)

    # directory listing
    audit["checks"]["directory_listing"] = check_directory_listing(target_url)
    time.sleep(SLEEP_BETWEEN_REQUESTS)

    # plugin probes (check homepage for backup/security plugins first)
    audit["checks"]["homepage_backup_plugins"] = detect_backup_plugins(resp.text if resp else "")
    time.sleep(SLEEP_BETWEEN_REQUESTS)

    audit["checks"]["plugin_probes"] = probe_plugins(target_url, plugin_probes=COMMON_PLUGIN_PROBES)
    time.sleep(SLEEP_BETWEEN_REQUESTS)

    # login / registration / wp-cron
    audit["checks"]["registration"] = check_registration_enabled(target_url)
    time.sleep(SLEEP_BETWEEN_REQUESTS)
    audit["checks"]["wp_login"] = check_wp_login_presence(target_url)
    time.sleep(SLEEP_BETWEEN_REQUESTS)
    audit["checks"]["wp_cron"] = {"status": None}
    r = safe_get(urljoin(target_url + "/", "wp-cron.php"))
    if r:
        audit["checks"]["wp_cron"] = {"status": r.status_code, "body_snippet": (r.text or "")[:400]}

    time.sleep(SLEEP_BETWEEN_REQUESTS)

    # detect cloudflare
    audit["checks"]["cloudflare"] = detect_cloudflare(resp)

    # uploads php exec probe
    test_php_url = urljoin(target_url + "/", "wp-content/uploads/.wp_audit_test.php")
    rprobe = safe_get(test_php_url)
    audit["checks"]["uploads_php_exec"] = {"test_url": test_php_url, "status": rprobe.status_code if rprobe else None}

    time.sleep(SLEEP_BETWEEN_REQUESTS)

    # robots/sitemap
    r_robots = safe_get(urljoin(target_url + "/", "robots.txt"))
    audit["checks"]["robots.txt"] = {"status": r_robots.status_code if r_robots else None, "body": (r_robots.text[:1200] if r_robots else None)}
    sitemap = None
    if r_robots and r_robots.status_code == 200:
        m = re.search(r"Sitemap:\s*(https?://\S+)", r_robots.text, re.I)
        if m:
            sitemap = m.group(1)
    else:
        r_smap = safe_get(urljoin(target_url + "/", "sitemap.xml"))
        if r_smap and r_smap.status_code == 200:
            sitemap = urljoin(target_url + "/", "sitemap.xml")
    audit["checks"]["sitemap"] = sitemap

    # -----------------------------
    # WPScan integrations
    # -----------------------------
    audit["vuln_data"] = {}
    if use_wpscan_cli:
        cli_res = run_wpscan_cli(target_url, api_token=wpscan_key)
        audit["vuln_data"]["wpscan_cli"] = cli_res
        if isinstance(cli_res, dict) and not cli_res.get("error"):
            wpinfo = cli_res.get("wordpress", {})
            if wpinfo and isinstance(wpinfo, dict):
                version = wpinfo.get("version", {}).get("number") if isinstance(wpinfo.get("version"), dict) else None
                if version:
                    audit["checks"]["version_detection"]["wpscan_cli_version"] = version
            plugins = cli_res.get("plugins", {})
            if plugins and isinstance(plugins, dict):
                audit["vuln_data"].setdefault("wpscan_cli_plugins", {})
                for pslug, pdata in plugins.items():
                    audit["vuln_data"]["wpscan_cli_plugins"][pslug] = pdata
                    vulns = pdata.get("vulnerabilities")
                    if vulns:
                        for v in vulns:
                            title = v.get("title") or v.get("name") or "vulnerability"
                            audit.setdefault("warnings", []).append({
                                "type": "plugin_vuln",
                                "plugin": pslug,
                                "title": title,
                                "reference": v
                            })
    else:
        audit["vuln_data"]["wpscan_cli"] = {"note": "wpscan CLI not run (use --use-wpscan-cli to enable)"}

    if wpscan_key:
        try:
            api_wp = query_wpscan_wordpress(target_url, wpscan_key)
            audit["vuln_data"]["wpscan_api"] = {"wordpress": api_wp}
        except Exception as e:
            audit["vuln_data"]["wpscan_api"] = {"error": str(e)}

        audit["vuln_data"].setdefault("wpscan_api_plugins", {})
        for p in audit["checks"].get("plugin_probes", []):
            slug = None
            try:
                slug = p["path"].split("/")[2] if len(p["path"].split("/")) > 2 else None
            except Exception:
                slug = None
            if slug:
                res = query_wpscan_plugin(slug, wpscan_key)
                audit["vuln_data"]["wpscan_api_plugins"][slug] = res
                time.sleep(1.0)

        theme_slug = None
        if resp and resp.text:
            m = re.search(r'/wp-content/themes/([^/]+)/', resp.text or "", re.I)
            if m:
                theme_slug = m.group(1)
        if theme_slug:
            audit["vuln_data"]["wpscan_api_theme"] = query_wpscan_theme(theme_slug, wpscan_key)
    else:
        audit["vuln_data"]["wpscan_api"] = {"note": "No WPScan API key provided; pass --wpscan-key to enable API lookups."}

    if patchstack_key:
        audit["vuln_data"]["patchstack_summary"] = {"note": "Patchstack integration provided; implement further queries as needed."}
    else:
        audit["vuln_data"]["patchstack_summary"] = {"note": "No Patchstack key provided."}

    audit["cves"] = {}
    candidates = []
    if audit["checks"]["version_detection"].get("meta"):
        candidates.append("wordpress " + str(audit["checks"]["version_detection"].get("meta")))
    for p in audit["checks"].get("plugin_probes", []):
        slug = p["path"].split("/")[2] if len(p["path"].split("/")) > 2 else None
        if slug:
            candidates.append(slug)
    audit["cves"]["nvd"] = {}
    for cand in candidates[:6]:
        res = nvd_search(cand)
        audit["cves"]["nvd"][cand] = res
        time.sleep(1.2)

    # scoring & recommendations
    audit["score"] = compute_score(audit["checks"])
    audit["recommendations"] = build_recommendations(audit["checks"])

    audit["summary"] = {
        "target": target_url,
        "is_wordpress": audit["checks"]["is_wordpress"],
        "score": audit["score"],
        "top_recommendations": audit["recommendations"][:6],
    }

    return audit

# ==============================
# Reporting helpers (folder structured)
# ==============================
def save_reports(audit, base_dir="reports"):
    """
    Save audit reports in a structured folder: reports/<target_netloc>/
    Returns JSON and HTML paths.
    """
    netloc = urlparse(audit['target']).netloc.replace(":", "_")
    target_dir = os.path.join(base_dir, netloc)
    os.makedirs(target_dir, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    json_file = os.path.join(target_dir, f"wp_audit_{ts}.json")
    html_file = os.path.join(target_dir, f"wp_audit_{ts}.html")

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2)

    html_content = "<html><head><meta charset='utf-8'><title>WP Audit</title></head><body>"
    html_content += f"<h1>WP Audit: {html.escape(audit['target'])}</h1>"
    html_content += f"<p>Generated: {html.escape(audit['timestamp'])}</p>"
    html_content += "<h2>Summary</h2>"
    html_content += f"<pre>{html.escape(json.dumps(audit['summary'], indent=2))}</pre>"
    html_content += "<h2>Checks</h2>"
    html_content += f"<pre>{html.escape(json.dumps(audit['checks'], indent=2)[:4000])}</pre>"
    html_content += "<h2>Recommendations</h2><ul>"
    for r in audit.get("recommendations", []):
        html_content += f"<li>{html.escape(r)}</li>"
    html_content += "</ul>"
    html_content += "<h2>Vulnerability Data (WPScan)</h2>"
    html_content += "<h3>WPScan CLI</h3><pre>"
    html_content += html.escape(json.dumps(audit.get("vuln_data", {}).get("wpscan_cli", {}), indent=2)[:10000])
    html_content += "</pre>"
    html_content += "<h3>WPScan API (plugins)</h3><pre>"
    html_content += html.escape(json.dumps(audit.get("vuln_data", {}).get("wpscan_api_plugins", {}), indent=2)[:10000])
    html_content += "</pre>"
    html_content += "<h3>NVD (selected)</h3><pre>"
    html_content += html.escape(json.dumps(audit.get("cves", {}).get("nvd", {}), indent=2)[:8000])
    html_content += "</pre>"
    html_content += "</body></html>"

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    return json_file, html_file

# ==============================
# CLI
# ==============================
def parse_args():
    p = argparse.ArgumentParser(description="Comprehensive passive WordPress auditor with WPScan options")
    p.add_argument("--target", "-t", help="Single target URL (e.g. https://example.com)")
    p.add_argument("--targets", help="File with newline-separated targets")
    p.add_argument("--wpscan-key", help="WPScan API token (optional)", default=None)
    p.add_argument("--use-wpscan-cli", action="store_true", help="Run local WPScan CLI (if installed) -- outputs JSON in vuln_data")
    p.add_argument("--patchstack-key", help="Patchstack API key (optional)", default=None)
    p.add_argument("--output-dir", help="Output directory for structured reports", default="reports")
    p.add_argument("--pretty", action="store_true", help="Print human summary to stdout")
    p.add_argument("--verbose", action="store_true", help="Verbose mode")
    return p.parse_args()

def main():
    args = parse_args()
    global ENABLE_VERBOSE
    ENABLE_VERBOSE = args.verbose

    print("WP Full Audit — passive checks only (WPScan optional)")
    print("ETHICS: Only scan sites you own or have explicit permission to test.")
    if not args.target and not args.targets:
        print("Provide --target or --targets file")
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target.strip())
    if args.targets:
        with open(args.targets, "r", encoding="utf-8") as f:
            for l in f:
                l = l.strip()
                if l:
                    targets.append(l)

    all_results = {"generated_at": short(time.time()), "results": []}
    for t in targets:
        try:
            a = audit_site(t, wpscan_key=args.wpscan_key, use_wpscan_cli=args.use_wpscan_cli, patchstack_key=args.patchstack_key, verbose=args.verbose)
            all_results["results"].append(a)
            if args.pretty:
                print_summary(a)
            json_file, html_file = save_reports(a, base_dir=args.output_dir)
            if args.pretty:
                print(f"Saved JSON: {json_file}, HTML: {html_file}")
            time.sleep(1.0)
        except KeyboardInterrupt:
            print("Interrupted")
            break
        except Exception as e:
            print(f"[!] Error scanning {t}: {e}")
            all_results["results"].append({"target": t, "error": str(e)})

    agg_file = os.path.join(args.output_dir, f"wp_audit_aggregate_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
    os.makedirs(args.output_dir, exist_ok=True)
    with open(agg_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"[+] Aggregate results saved to {agg_file}")

if __name__ == "__main__":
    main()
