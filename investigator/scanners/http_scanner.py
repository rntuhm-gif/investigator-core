"""HTTP/web scanner — security headers, technology fingerprinting, directory checks."""
import re
import json
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone
from .base import BaseScanner
from ..utils.color_out import cprint

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Common security headers to check
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# WAF fingerprints (very simple, for awareness only)
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray"],
    "Akamai": ["akamai", "akamai-ghost"],
    "AWS CloudFront": ["x-amz-cf-id", "cloudfront"],
    "Sucuri": ["x-sucuri-id"],
    "ModSecurity": ["mod_security", "NYOB"],
    "F5 BIG-IP": ["BigIP", "F5-TrafficShield"],
}

# Tech fingerprint patterns in response body/headers
TECH_SIGNATURES = [
    (re.compile(r"wp-content|wordpress", re.I), "WordPress"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"joomla", re.I), "Joomla"),
    (re.compile(r"X-Powered-By: PHP", re.I), "PHP"),
    (re.compile(r"X-Powered-By: ASP\.NET", re.I), "ASP.NET"),
    (re.compile(r"server: nginx", re.I), "Nginx"),
    (re.compile(r"server: Apache", re.I), "Apache"),
    (re.compile(r"server: Microsoft-IIS", re.I), "IIS"),
    (re.compile(r"express", re.I), "Express.js"),
    (re.compile(r"django", re.I), "Django"),
    (re.compile(r"flask", re.I), "Flask"),
    (re.compile(r"laravel", re.I), "Laravel"),
    (re.compile(r"react", re.I), "React"),
    (re.compile(r"angular", re.I), "Angular"),
    (re.compile(r"vue", re.I), "Vue.js"),
    (re.compile(r"jquery", re.I), "jQuery"),
    (re.compile(r"bootstrap", re.I), "Bootstrap"),
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
]


class HttpScanner(BaseScanner):
    def __init__(self, timeout=8.0, verbose=False):
        self.timeout = timeout
        self.verbose = verbose

    def scan(self, target, check_headers=True, check_tech=True, check_https=True,
             check_redirects=True, **kwargs):
        if not HAS_REQUESTS:
            return {"error": "requests not installed", "target": target}

        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        cprint(f"[*] HTTP scan: {url}", "cyan")

        start = datetime.now(timezone.utc)
        results = {
            "url": url, "host": urlparse(url).hostname,
            "checks": {}, "technologies": [], "security_headers": {},
            "missing_headers": [], "redirect_chain": [], "waf": None,
        }

        try:
            resp = requests.get(
                url, timeout=self.timeout, allow_redirects=check_redirects,
                verify=False, headers={"User-Agent": "Mozilla/5.0 (investigator/0.2)"}
            )
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "target": target}

        results["status_code"] = resp.status_code
        results["final_url"] = resp.url
        results["content_length"] = len(resp.content)
        results["response_time_ms"] = int(resp.elapsed.total_seconds() * 1000)

        # Redirect chain
        if check_redirects and resp.history:
            results["redirect_chain"] = [
                {"url": r.url, "status": r.status_code, "location": r.headers.get("Location", "")}
                for r in resp.history
            ]

        # Security headers
        if check_headers:
            for header in SECURITY_HEADERS:
                value = resp.headers.get(header)
                if value:
                    results["security_headers"][header] = value
                else:
                    results["missing_headers"].append(header)

        # Technology detection
        if check_tech:
            header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            body_blob = resp.text[:200000]  # cap to first 200KB
            combined = header_blob + "\n" + body_blob
            seen = set()
            for pattern, tech in TECH_SIGNATURES:
                if tech in seen:
                    continue
                if pattern.search(combined):
                    results["technologies"].append(tech)
                    seen.add(tech)

        # WAF detection
        for waf, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in str(resp.headers).lower():
                    results["waf"] = waf
                    break
            if results["waf"]:
                break

        # Cookies analysis
        results["cookies"] = []
        for cookie in resp.cookies:
            results["cookies"].append({
                "name": cookie.name, "value": cookie.value[:50],
                "secure": cookie.secure, "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            })

        # Server header
        results["server"] = resp.headers.get("Server", "")
        results["x_powered_by"] = resp.headers.get("X-Powered-By", "")

        results["scan_metadata"] = {
            "scanner": "HttpScanner",
            "started_at": start.isoformat(),
            "duration_seconds": (datetime.now(timezone.utc) - start).total_seconds(),
        }

        return {"hosts": [{"host": results["host"], "status": "up", "http": results}]}

    def summarize(self, results):
        if "error" in results and not results.get("hosts"):
            return f"HTTP scan failed: {results['error']}"
        for h in results.get("hosts", []):
            http = h.get("http", {})
            techs = ", ".join(http.get("technologies", [])) or "none"
            missing = len(http.get("missing_headers", []))
            waf = http.get("waf", "")
            waf_str = f" | WAF: {waf}" if waf else ""
            return f"HTTP {http.get('status_code', '?')} | techs: {techs} | missing headers: {missing}{waf_str}"
        return "no data"

