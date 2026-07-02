"""PCAP traffic analysis via tshark."""
import os
import subprocess
from pathlib import Path
from ..utils.color_out import cprint


class PcapAnalyzer:
    def __init__(self, tshark_path="tshark"):
        self.tshark_path = tshark_path
        self._available = os.system(f"which {tshark_path} > /dev/null 2>&1") == 0

    @property
    def available(self):
        return self._available

    def analyze(self, pcap_path, **kwargs):
        path = Path(pcap_path)
        if not path.exists():
            return {"error": f"File not found: {pcap_path}"}
        if not self._available:
            return {"error": "tshark not installed. Run: sudo apt install tshark"}

        cprint(f"[*] Analyzing PCAP: {pcap_path}", "cyan")
        results = {"file": str(path), "file_size_bytes": path.stat().st_size}
        results["packet_count"] = self._run(
            f"tshark -r '{pcap_path}' -T fields -e frame.number 2>/dev/null | wc -l"
        )
        results["protocol_hierarchy"] = self._run(f"tshark -r '{pcap_path}' -qz io,phs 2>/dev/null")
        results["endpoints"] = self._run(f"tshark -r '{pcap_path}' -qz conv,ip 2>/dev/null")
        results["dns_queries"] = self._run(
            f"tshark -r '{pcap_path}' -Y 'dns.flags.response==0' -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn"
        )
        results["http_requests"] = self._run(
            f"tshark -r '{pcap_path}' -Y 'http.request' -T fields -e http.request.method -e http.request.uri -e http.host 2>/dev/null"
        )
        return results

    def _run(self, cmd):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return r.stdout.strip()
        except Exception:
            return "(timeout)"

    def summarize(self, results):
        if "error" in results:
            return f"PCAP analysis failed: {results['error']}"
        pkts = results.get("packet_count", "?")
        return f"PCAP: {pkts} packets"

