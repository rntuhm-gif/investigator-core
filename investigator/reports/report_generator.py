"""Generate case reports in JSON, text, or HTML format."""
import json
from datetime import datetime, timezone
from pathlib import Path
from ..utils.color_out import cprint


class ReportGenerator:
    @staticmethod
    def generate_json(case, scan_results=None, analysis_results=None, output_path=""):
        report = {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "case": case.to_dict() if hasattr(case, "to_dict") else case,
            "scan_results": scan_results or {},
            "analysis_results": analysis_results or {},
        }
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            cprint(f"[+] Report saved to {output_path}", "green")
            return output_path
        return json.dumps(report, indent=2, default=str)

    @staticmethod
    def generate_text(case, scan_results=None, analysis_results=None):
        lines = []
        lines.append("=" * 60)
        lines.append("INVESTIGATION REPORT")
        lines.append("=" * 60)
        lines.append("")
        d = case.to_dict() if hasattr(case, "to_dict") else case
        lines.append(f"Case: {d.get('name', 'N/A')}")
        lines.append(f"Description: {d.get('description', 'N/A')}")
        lines.append(f"Status: {d.get('status', 'N/A')}")
        lines.append(f"Created: {d.get('created_at', 'N/A')}")
        lines.append(f"Investigators: {', '.join(d.get('investigators', ['N/A']))}")
        lines.append("")

        findings = d.get("findings", [])
        if findings:
            lines.append("--- FINDINGS ---")
            for i, f in enumerate(findings, 1):
                lines.append(f"  {i}. {f.get('summary', 'N/A')}")
            lines.append("")

        evidence = d.get("evidence", [])
        if evidence:
            lines.append("--- EVIDENCE LOG ---")
            for i, e in enumerate(evidence, 1):
                lines.append(f"  {i}. [{e.get('type', '?')}] {e.get('source', 'N/A')}")
            lines.append("")

        if scan_results:
            lines.append("--- SCAN RESULTS ---")
            for h in scan_results.get("hosts", []):
                lines.append(f"  Host: {h.get('host', '?')} ({h.get('status', '?')})")
                for p in h.get("ports", []):
                    if p.get("state") == "open":
                        lines.append(
                            f"    Port {p['port']}/{p['protocol']} - {p['name']} "
                            f"{p.get('product', '')} {p.get('version', '')}"
                        )
            lines.append("")

        lines.append("=" * 60)
        lines.append("End of Report")
        return "\n".join(lines)

    @staticmethod
    def generate_html(case, scan_results=None, analysis_results=None):
        text = ReportGenerator.generate_text(case, scan_results, analysis_results)
        safe = text.replace("\n", "<br>\n").replace("  ", "&nbsp;&nbsp;")
        return (
            "<!DOCTYPE html>\n"
            "<html><head><meta charset='utf-8'><title>Investigation Report</title>\n"
            "<style>body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;"
            "padding:2em;}pre{white-space:pre-wrap;word-wrap:break-word;}</style>\n"
            "</head><body><pre>\n"
            f"{safe}\n"
            "</pre></body></html>"
        )

