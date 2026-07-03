"""Extract Indicators of Compromise (IOCs) from files or pcap dumps.

Parses emails, URLs, IP addresses, domains, hashes (MD5/SHA1/SHA256),
and CVE references from arbitrary text/PCAP content.
"""
import re
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from ..utils.color_out import cprint

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# Regex patterns
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_URL = re.compile(r"https?://[^\s<>'\"`)\]},;]+", re.IGNORECASE)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Defang/Refang helpers
DEFBANG = {"http": "hxxp", "https": "hxxps", ".": "[.]", "@": "[@]"}


def refang(text):
    """Reverse common defanging so IOCs in reports can be extracted."""
    text = re.sub(r"hxxps?", "http", text, flags=re.IGNORECASE)
    text = text.replace("[.]", ".")
    text = text.replace("(.)", ".")
    text = text.replace("[@]", "@")
    text = text.replace("[at]", "@")
    return text


class IOCHarvester:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def extract(self, source, source_type="auto", compute_file_hashes=True, refang_input=True):
        """Extract IOCs from a file or string.

        Args:
            source: file path or raw text
            source_type: 'file', 'text', or 'auto' (detect)
            compute_file_hashes: when source is a file, compute MD5/SHA1/SHA256
            refang_input: attempt to defang reversal on input
        """
        if source_type == "auto":
            source_type = "file" if Path(source).exists() else "text"

        if source_type == "file":
            text = Path(source).read_text(errors="ignore")
            path = source
        else:
            text = source
            path = None

        if refang_input:
            text = refang(text)

        iocs = {
            "source": path or "<inline>",
            "extracted_at": datetime.now(timezone.utc).isoformat(),
            "emails": sorted(set(RE_EMAIL.findall(text))),
            "urls": sorted(set(RE_URL.findall(text))),
            "ipv4": sorted(set(self._filter_ips(RE_IPV4.findall(text)))),
            "domains": sorted(set(self._filter_domains(RE_DOMAIN.findall(text)))),
            "md5": sorted(set(m.lower() for m in RE_MD5.findall(text))),
            "sha1": sorted(set(s.lower() for s in RE_SHA1.findall(text))),
            "sha256": sorted(set(s.lower() for s in RE_SHA256.findall(text))),
            "cves": sorted(set(c.upper() for c in RE_CVE.findall(text))),
        }

        # File hashes
        if path and compute_file_hashes:
            iocs["file_hashes"] = self._hash_file(path)
        else:
            iocs["file_hashes"] = {}

        # Stats
        iocs["stats"] = {
            "emails": len(iocs["emails"]),
            "urls": len(iocs["urls"]),
            "ipv4": len(iocs["ipv4"]),
            "domains": len(iocs["domains"]),
            "hashes": len(iocs["md5"]) + len(iocs["sha1"]) + len(iocs["sha256"]),
            "cves": len(iocs["cves"]),
        }
        return iocs

    def _filter_ips(self, ips):
        """Drop invalid octets and obvious broadcast/loopback."""
        out = []
        for ip in ips:
            parts = ip.split(".")
            if len(parts) != 4:
                continue
            try:
                octets = [int(p) for p in parts]
            except ValueError:
                continue
            if any(o > 255 for o in octets):
                continue
            # Skip 0.0.0.0 and pure 255.255.255.255
            if ip in ("0.0.0.0", "255.255.255.255"):
                continue
            out.append(ip)
        return out

    def _filter_domains(self, domains):
        """Drop likely false positives (file extensions, version numbers)."""
        out = []
        skip_suffixes = (".txt", ".log", ".json", ".html", ".xml", ".py", ".md")
        for d in domains:
            d_l = d.lower()
            if d_l.endswith(skip_suffixes):
                continue
            if d_l.startswith(("127.", "0.0.0", "255.")):
                continue
            if d_l in ("example.com", "test.com", "localhost"):
                continue
            # Must have at least one dot and a 2+ char TLD
            if "." not in d_l:
                continue
            tld = d_l.rsplit(".", 1)[-1]
            if len(tld) < 2:
                continue
            out.append(d_l)
        return out

    def _hash_file(self, path):
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            return {
                "md5": md5.hexdigest(),
                "sha1": sha1.hexdigest(),
                "sha256": sha256.hexdigest(),
            }
        except OSError as e:
            return {"error": str(e)}

    def summarize(self, iocs):
        s = iocs.get("stats", {})
        return (f"IOCs: {s.get('emails',0)} emails, {s.get('urls',0)} URLs, "
                f"{s.get('ipv4',0)} IPs, {s.get('domains',0)} domains, "
                f"{s.get('hashes',0)} hashes, {s.get('cves',0)} CVEs")

