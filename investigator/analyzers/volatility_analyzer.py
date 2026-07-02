"""Memory analysis via Volatility 3."""
import os
import subprocess
from pathlib import Path
from ..utils.color_out import cprint


class VolatilityAnalyzer:
    def __init__(self, vol_path="vol"):
        self.vol_path = vol_path
        self._available = os.system(f"which {vol_path} > /dev/null 2>&1") == 0

    @property
    def available(self):
        return self._available

    def analyze(self, memory_dump, profile=None, **kwargs):
        path = Path(memory_dump)
        if not path.exists():
            return {"error": f"File not found: {memory_dump}"}
        if not self._available:
            return {"error": "Volatility 3 not installed. Run: pip install volatility3"}

        cprint(f"[*] Analyzing memory dump: {memory_dump}", "cyan")
        os_type = profile or self._detect_os(path)
        results = {
            "file": str(path),
            "file_size_bytes": path.stat().st_size,
            "os_detected": os_type,
        }

        plugins = []
        if os_type.startswith("windows"):
            plugins = [
                "windows.info", "windows.netscan", "windows.pslist",
                "windows.cmdline", "windows.malfind",
            ]
        elif os_type.startswith("linux"):
            plugins = ["linux.info", "linux.pslist", "linux.bash", "linux.netstat"]
        elif os_type.startswith("mac"):
            plugins = ["mac.info", "mac.pslist", "mac.netstat"]

        plugin_results = {}
        for plugin in plugins:
            output = self._run_vol(plugin, path)
            if output:
                plugin_results[plugin] = output
        results["plugins"] = plugin_results
        return results

    def _detect_os(self, path):
        output = self._run_vol("banner", path) or self._run_vol("windows.info", path) or ""
        if "windows" in output.lower():
            return "windows"
        if "linux" in output.lower():
            return "linux"
        if "mac" in output.lower() or "darwin" in output.lower():
            return "mac"
        return "unknown"

    def _run_vol(self, plugin, path):
        try:
            r = subprocess.run(
                [self.vol_path, "-f", str(path), plugin],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                return r.stdout.strip()[:3000]
            return f"(error: {r.stderr.strip()[:200]})"
        except Exception:
            return "(timeout)"

    def summarize(self, results):
        if "error" in results:
            return f"Memory analysis failed: {results['error']}"
        return f"Memory: {results.get('os_detected', '?')}, {len(results.get('plugins', {}))} plugins run"

