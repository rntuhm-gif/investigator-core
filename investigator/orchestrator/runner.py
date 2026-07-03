"""Workflow runner — executes a Workflow step by step, passing context between steps."""
import time
from datetime import datetime, timezone
from ..scanners import NmapScanner, PortScanner, HttpScanner, SubdomainEnumerator
from ..analyzers import PcapAnalyzer, VolatilityAnalyzer
from ..analyzers.ioc_harvester import IOCHarvester
from ..case_manager import CaseManager
from ..utils.color_out import cprint


# Tool registry — maps tool name -> callable that takes (context, **args) -> result
TOOLS = {}


def register_tool(name):
    def deco(fn):
        TOOLS[name] = fn
        return fn
    return deco


@register_tool("nmap")
def _t_nmap(ctx, **args):
    s = NmapScanner(verbose=ctx.get("verbose", False))
    return s.scan(**args)


@register_tool("portscan")
def _t_portscan(ctx, **args):
    s = PortScanner(verbose=ctx.get("verbose", False))
    return s.scan(**args)


@register_tool("http")
def _t_http(ctx, **args):
    s = HttpScanner(verbose=ctx.get("verbose", False))
    return s.scan(**args)


@register_tool("subdomain")
def _t_subdomain(ctx, **args):
    s = SubdomainEnumerator(verbose=ctx.get("verbose", False))
    return s.scan(**args)


@register_tool("pcap")
def _t_pcap(ctx, **args):
    a = PcapAnalyzer()
    return a.analyze(**args) if a.available else {"error": "tshark not installed"}


@register_tool("memory")
def _t_memory(ctx, **args):
    a = VolatilityAnalyzer()
    return a.analyze(**args) if a.available else {"error": "volatility3 not installed"}


@register_tool("ioc")
def _t_ioc(ctx, **args):
    h = IOCHarvester()
    return h.extract(**args)


class WorkflowRunner:
    def __init__(self, workflow, case_manager=None, verbose=False):
        self.workflow = workflow
        self.cm = case_manager or CaseManager()
        self.verbose = verbose
        self.context = {"target": workflow.target, "verbose": verbose}
        self.history = []
        self.started_at = None

    def run(self):
        cprint(f"\n[+] Workflow: {self.workflow.name}", "bold")
        if self.workflow.description:
            cprint(f"    {self.workflow.description}", "gray")
        cprint(f"    Steps: {len(self.workflow.steps)}", "gray")
        cprint("─" * 60, "gray")

        self.started_at = datetime.now(timezone.utc)

        # Ensure case exists if case_name given
        if self.workflow.case_name:
            case = self.cm.load(self.workflow.case_name)
            if not case:
                cprint(f"[*] Auto-creating case '{self.workflow.case_name}'", "cyan")
                self.cm.create(self.workflow.case_name, description=f"Auto-created by workflow '{self.workflow.name}'")
            self.context["case"] = self.workflow.case_name

        stop = False
        for i, step in enumerate(self.workflow.steps, 1):
            if stop:
                break
            cprint(f"\n[{i}/{len(self.workflow.steps)}] Step: {step.name} (tool: {step.tool})", "yellow")
            t0 = time.time()
            try:
                if step.tool not in TOOLS:
                    raise ValueError(f"unknown tool '{step.tool}'. available: {sorted(TOOLS)}")
                # Bind default target if arg is "TARGET"
                resolved_args = {k: (v if v != "TARGET" else self.context.get("target", v))
                                 for k, v in step.args.items()}
                result = TOOLS[step.tool](self.context, **resolved_args)
                self.context[step.bind] = result
                duration = time.time() - t0
                self.history.append({
                    "step": step.name, "tool": step.tool, "ok": True,
                    "duration": duration, "result_summary": _summarize_result(step.tool, result),
                })
                cprint(f"    ✓ {self.history[-1]['result_summary']} ({duration:.1f}s)", "green")

                # Attach to case
                if self.workflow.case_name:
                    self.cm.add_evidence(self.workflow.case_name, {
                        "type": f"{step.tool}_workflow",
                        "source": str(resolved_args),
                        "summary": self.history[-1]["result_summary"],
                        "step": step.name,
                    })

            except Exception as e:
                duration = time.time() - t0
                self.history.append({
                    "step": step.name, "tool": step.tool, "ok": False,
                    "duration": duration, "error": str(e),
                })
                cprint(f"    ✗ Failed: {e} ({duration:.1f}s)", "red")
                if step.on_fail == "stop":
                    stop = True
                elif step.on_fail == "skip_remaining":
                    stop = True
                    cprint("[!] Skipping remaining steps", "yellow")

        # Final case update
        if self.workflow.case_name:
            self.cm.add_finding(self.workflow.case_name, {
                "summary": f"Workflow '{self.workflow.name}' completed",
                "details": {
                    "started_at": self.started_at.isoformat(),
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "steps_run": len(self.history),
                    "steps_ok": sum(1 for h in self.history if h["ok"]),
                },
            })

        cprint("\n" + "─" * 60, "gray")
        ok = sum(1 for h in self.history if h["ok"])
        cprint(f"[+] Workflow complete: {ok}/{len(self.history)} steps succeeded", "green" if ok == len(self.history) else "yellow")
        return self.context, self.history


def _summarize_result(tool, result):
    if not isinstance(result, dict):
        return str(result)[:80]
    if "error" in result and not result.get("hosts"):
        return f"error: {result['error']}"
    if tool == "nmap":
        hosts = result.get("hosts", [])
        opens = sum(1 for h in hosts for p in h.get("ports", []) if p.get("state") == "open")
        return f"nmap: {len(hosts)} host(s), {opens} open port(s)"
    if tool == "portscan":
        for h in result.get("hosts", []):
            m = h.get("scan_metadata", {})
            return f"portscan: {m.get('ports_open', 0)} open / {m.get('ports_scanned', 0)} scanned"
        return "portscan: no hosts"
    if tool == "http":
        for h in result.get("hosts", []):
            http = h.get("http", {})
            return f"http: {http.get('status_code', '?')} | techs: {', '.join(http.get('technologies', [])) or 'none'}"
        return "http: no data"
    if tool == "subdomain":
        m = result.get("scan_metadata", {})
        return f"subdomain: {m.get('subdomains_found', 0)} found"
    if tool == "ioc":
        s = result.get("stats", {})
        return f"ioc: {s.get('emails',0)} emails, {s.get('urls',0)} URLs, {s.get('ipv4',0)} IPs, {s.get('domains',0)} domains"
    if tool == "pcap":
        return f"pcap: {result.get('packet_count', '?')} packets"
    if tool == "memory":
        return f"memory: {result.get('os_detected', '?')}, {len(result.get('plugins', {}))} plugins"
    return "ok"

