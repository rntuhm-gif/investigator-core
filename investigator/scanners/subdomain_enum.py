"""Subdomain enumeration via DNS brute-force and crt.sh transparency log."""
import socket
import concurrent.futures
import threading
import json
import urllib.request
from datetime import datetime, timezone
from .base import BaseScanner
from ..utils.color_out import cprint

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "webmail",
    "login", "admin", "administrator", "dashboard", "panel", "cpanel",
    "api", "dev", "development", "staging", "stage", "test", "testing",
    "beta", "demo", "sandbox", "qa", "uat", "pre", "preprod",
    "blog", "wordpress", "wp", "joomla", "drupal", "wiki",
    "shop", "store", "ecommerce", "cart", "pay", "payment",
    "support", "help", "helpdesk", "ticket", "tickets",
    "forum", "community", "social", "chat", "irc",
    "git", "github", "gitlab", "bitbucket", "svn", "code", "repo",
    "ci", "cd", "jenkins", "travis", "drone", "build",
    "staging-api", "dev-api", "test-api", "internal-api",
    "db", "database", "mysql", "postgres", "postgresql", "redis", "mongo", "mongodb", "elastic", "elasticsearch",
    "ldap", "auth", "sso", "oauth", "identity", "id",
    "vpn", "remote", "gateway", "gw", "proxy",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "cloud", "aws", "azure", "gcp", "s3", "bucket",
    "mobile", "m", "app", "application",
    "docs", "doc", "documentation", "confluence", "jira",
    "monitor", "monitoring", "nagios", "zabbix", "grafana", "kibana", "prometheus",
    "log", "logs", "logging", "elk", "splunk",
    "backup", "bak", "old", "new", "v1", "v2",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "email", "smtp-relay",
    "remote", "rdp", "ssh", "shell", "terminal",
    "search", "elastic", "solr",
    "www2", "ww1", "web", "web1", "web2",
    "intranet", "internal", "private", "corp", "corporate",
    "marketing", "sales", "crm", "erp", "hr",
    "training", "learn", "academy", "school",
    "video", "stream", "live", "meeting", "meet",
    "cdn1", "cdn2", "edge",
]


class SubdomainEnumerator(BaseScanner):
    def __init__(self, timeout=3.0, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self._lock = threading.Lock()
        self._found = []

    def scan(self, target, wordlist=None, threads=50, use_crtsh=True, **kwargs):
        cprint(f"[*] Subdomain enumeration: {target}", "cyan")

        target = target.lower().strip()
        # Strip protocol if present
        if target.startswith(("http://", "https://")):
            target = urlparse(target).hostname or target

        words = wordlist or DEFAULT_WORDLIST
        self._found = []

        start = datetime.now(timezone.utc)
        results = {"hosts": []}

        # DNS brute
        cprint(f"[*] DNS brute with {len(words)} prefixes ({threads} threads)", "gray")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(self._check, f"{w}.{target}"): w for w in words}
            for fut in concurrent.futures.as_completed(futures):
                pass  # results collected inside _check

        # crt.sh
        if use_crtsh and HAS_REQUESTS:
            cprint("[*] Querying crt.sh transparency log...", "gray")
            self._crtsh(target)

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        # Dedupe
        unique = {}
        for entry in self._found:
            unique[entry["host"]] = entry

        for host, info in sorted(unique.items()):
            results["hosts"].append({
                "host": host, "status": "up", "subdomain_info": info,
            })

        results["scan_metadata"] = {
            "scanner": "SubdomainEnumerator",
            "target": target,
            "wordlist_size": len(words),
            "subdomains_found": len(unique),
            "duration_seconds": elapsed,
            "started_at": start.isoformat(),
        }
        return results

    def _check(self, hostname):
        try:
            ip = socket.gethostbyname(hostname)
            with self._lock:
                if not any(e["host"] == hostname for e in self._found):
                    self._found.append({"host": hostname, "ip": ip, "source": "dns"})
            cprint(f"  [+] {hostname} -> {ip}", "green")
        except (socket.gaierror, socket.error):
            pass

    def _crtsh(self, target):
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        try:
            resp = requests.get(url, timeout=15, verify=False)
            if resp.status_code != 200:
                return
            data = resp.json()
            added = 0
            for entry in data:
                name = entry.get("name_value", "").strip().lower()
                if not name or "*" in name:
                    continue
                for sub in name.split("\n"):
                    sub = sub.strip()
                    if not sub or "*" in sub or not sub.endswith(target):
                        continue
                    with self._lock:
                        if not any(e["host"] == sub for e in self._found):
                            try:
                                ip = socket.gethostbyname(sub)
                                self._found.append({
                                    "host": sub, "ip": ip, "source": "crt.sh"
                                })
                                cprint(f"  [+] {sub} -> {ip} (crt.sh)", "cyan")
                                added += 1
                            except socket.gaierror:
                                pass
            cprint(f"  [*] crt.sh added {added} new subdomains", "gray")
        except Exception as e:
            cprint(f"  [!] crt.sh query failed: {e}", "yellow")

    def summarize(self, results):
        meta = results.get("scan_metadata", {})
        return f"{meta.get('subdomains_found', 0)} subdomains found in {meta.get('duration_seconds', 0):.1f}s"

