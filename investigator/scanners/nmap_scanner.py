"""Nmap scanner wrapping python-nmap."""
import nmap
from datetime import datetime, timezone
from .base import BaseScanner
from ..utils.color_out import cprint


class NmapScanner(BaseScanner):
    def __init__(self, nmap_binary="nmap", verbose=False):
        self.nm = nmap.PortScanner(nmap_search_path=(nmap_binary,))
        self.verbose = verbose

    def scan(self, target, ports="", args="-sV -sC -T4", sudo=False, timeout=300, **kwargs):
        cprint(f"[*] Scanning target: {target}", "cyan")
        if ports:
            cprint(f"[*] Ports: {ports}", "gray")
        cprint(f"[*] Arguments: {args}", "gray")

        scan_args = f"-o {args}" if sudo else args
        start = datetime.now(timezone.utc)

        try:
            result = self.nm.scan(
                hosts=target,
                ports=ports or None,
                arguments=scan_args,
                timeout=timeout,
                sudo=sudo,
            )
        except Exception as e:
            cprint(f"[!] Nmap scan failed: {e}", "red")
            return {"error": str(e), "target": target, "timestamp": start.isoformat()}

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        parsed = self._parse(result, target)
        parsed["scan_metadata"] = {
            "target": target,
            "ports": ports,
            "arguments": scan_args,
            "sudo": sudo,
            "started_at": start.isoformat(),
            "duration_seconds": elapsed,
        }
        return parsed

    def _parse(self, raw, target):
        hosts = []
        for host in self.nm.all_hosts():
            info = {
                "host": host,
                "hostname": "",
                "status": self.nm[host].state(),
                "os": {},
                "ports": [],
                "scripts": [],
            }
            if "hostnames" in self.nm[host]:
                hn = self.nm[host]["hostnames"]
                if isinstance(hn, list) and hn:
                    info["hostname"] = hn[0].get("name", "")
                elif isinstance(hn, dict):
                    info["hostname"] = hn.get("name", "")
            if "osmatch" in self.nm[host] and self.nm[host]["osmatch"]:
                best = self.nm[host]["osmatch"][0]
                info["os"] = {"name": best.get("name", ""), "accuracy": best.get("accuracy", "")}
            for proto in self.nm[host].all_protocols():
                for port in sorted(self.nm[host][proto].keys()):
                    svc = self.nm[host][proto][port]
                    info["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": svc.get("state", ""),
                        "name": svc.get("name", ""),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "extrainfo": svc.get("extrainfo", ""),
                    })
            if "hostscript" in self.nm[host]:
                for entry in self.nm[host]["hostscript"]:
                    info["scripts"].append({
                        "id": entry.get("id", ""),
                        "output": entry.get("output", ""),
                    })
            hosts.append(info)
        return {"hosts": hosts}

    def summarize(self, results):
        if "error" in results:
            return f"Scan failed: {results['error']}"
        hosts = results.get("hosts", [])
        open_ports = sum(1 for h in hosts for p in h.get("ports", []) if p["state"] == "open")
        return f"{len(hosts)} host(s), {open_ports} open port(s)"

