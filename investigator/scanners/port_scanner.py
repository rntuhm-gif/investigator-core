"""Custom threaded TCP port scanner.

Doesn't depend on nmap — useful when nmap isn't available or for fast
custom port ranges.
"""
import socket
import concurrent.futures
import threading
from datetime import datetime, timezone
from .base import BaseScanner
from ..utils.color_out import cprint


class PortScanner(BaseScanner):
    def __init__(self, timeout=1.0, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self._lock = threading.Lock()
        self._found = 0
        self._done = 0
        self._total = 0

    def scan(self, target, ports="1-1024", threads=100, banner_grab=False, **kwargs):
        cprint(f"[*] TCP port scan: {target}", "cyan")
        cprint(f"[*] Range: {ports} | threads: {threads}", "gray")

        target_ip = self._resolve(target)
        port_list = self._parse_ports(ports)
        self._total = len(port_list)
        self._done = 0
        self._found = 0

        start = datetime.now(timezone.utc)
        results = []

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {pool.submit(self._probe, target_ip, p, banner_grab): p for p in port_list}
                for fut in concurrent.futures.as_completed(futures):
                    r = fut.result()
                    if r:
                        results.append(r)
        except KeyboardInterrupt:
            cprint("\n[!] Scan interrupted", "yellow")
            return {"error": "interrupted", "hosts": []}

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        return {
            "hosts": [{
                "host": target_ip,
                "status": "up",
                "ports": results,
                "scan_metadata": {
                    "scanner": "PortScanner",
                    "ports_scanned": self._total,
                    "ports_open": self._found,
                    "duration_seconds": elapsed,
                    "started_at": start.isoformat(),
                },
            }]
        }

    def _probe(self, target_ip, port, banner_grab):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            if s.connect_ex((target_ip, port)) == 0:
                banner = ""
                if banner_grab:
                    try:
                        s.settimeout(2.0)
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    except Exception:
                        pass
                with self._lock:
                    self._found += 1
                result = {
                    "port": port, "protocol": "tcp", "state": "open",
                    "name": self._service_name(port), "banner": banner,
                }
                cprint(f"  [+] {port}/tcp open", "green")
                s.close()
                return result
            s.close()
        except Exception:
            pass
        finally:
            with self._lock:
                self._done += 1
        return None

    @staticmethod
    def _resolve(target):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return target

    @staticmethod
    def _parse_ports(spec):
        out = set()
        for chunk in spec.split(","):
            chunk = chunk.strip()
            if "-" in chunk:
                a, b = chunk.split("-", 1)
                out.update(range(int(a), int(b) + 1))
            else:
                out.add(int(chunk))
        return sorted(out)

    @staticmethod
    def _service_name(port):
        try:
            return socket.getservbyport(port, "tcp")
        except (OSError, OverflowError):
            return ""

    def summarize(self, results):
        if "error" in results and not results.get("hosts"):
            return f"Port scan failed: {results['error']}"
        hosts = results.get("hosts", [])
        for h in hosts:
            meta = h.get("scan_metadata", {})
            return f"{meta.get('ports_scanned', 0)} scanned, {meta.get('ports_open', 0)} open in {meta.get('duration_seconds', 0):.1f}s"
        return "no hosts"

