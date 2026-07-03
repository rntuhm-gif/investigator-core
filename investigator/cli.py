"""investigator CLI — main entry point."""
import argparse
import json
import os
import sys
import urllib3
from . import __version__
from .config import Config
from .case_manager import CaseManager
from .scanners import NmapScanner, PortScanner, HttpScanner, SubdomainEnumerator
from .analyzers import PcapAnalyzer, VolatilityAnalyzer, IOCHarvester
from .reports import ReportGenerator, EvidenceLocker
from .orchestrator import Workflow, WorkflowRunner
from .utils.color_out import cprint

# Quiet SSL warnings globally (intentional, for CTF/lab work)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def build_parser():
    p = argparse.ArgumentParser(
        prog="investigator",
        description="Multi-tool investigation orchestrator — scans, forensics, workflows, case management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"investigator {__version__}")
    p.add_argument("--verbose", "-v", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    # dashboard
    sub.add_parser("dashboard", help="Launch interactive dashboard")

    # case
    cp = sub.add_parser("case")
    cs = cp.add_subparsers(dest="case_action", required=True)
    cc = cs.add_parser("create")
    cc.add_argument("name")
    cc.add_argument("-d", "--description", default="")
    cc.add_argument("-i", "--investigators", nargs="*", default=[])
    cs.add_parser("list")
    cs.add_parser("close").add_argument("name")
    cs.add_parser("reopen").add_argument("name")
    cs.add_parser("delete").add_argument("name")

    # scan (default = nmap)
    sp = sub.add_parser("scan")
    sp.add_argument("target")
    sp.add_argument("-n", "--case", default="")
    sp.add_argument("-p", "--ports", default="")
    sp.add_argument("--args", default="-sV -sC -T4")
    sp.add_argument("--sudo", action="store_true")
    sp.add_argument("--timeout", type=int, default=300)
    sp.add_argument("-o", "--output", default="")

    # portscan
    pp = sub.add_parser("portscan")
    pp.add_argument("target")
    pp.add_argument("-p", "--ports", default="1-1024")
    pp.add_argument("-t", "--threads", type=int, default=100)
    pp.add_argument("--timeout", type=float, default=1.0)
    pp.add_argument("--banner", action="store_true")
    pp.add_argument("-n", "--case", default="")
    pp.add_argument("-o", "--output", default="")

    # http
    hp = sub.add_parser("http")
    hp.add_argument("target")
    hp.add_argument("-n", "--case", default="")
    hp.add_argument("-o", "--output", default="")

    # subdomain
    sb = sub.add_parser("subdomain")
    sb.add_argument("target")
    sb.add_argument("-n", "--case", default="")
    sb.add_argument("-t", "--threads", type=int, default=50)
    sb.add_argument("--no-crtsh", action="store_true")
    sb.add_argument("-w", "--wordlist", default="")
    sb.add_argument("-o", "--output", default="")

    # analyze
    ap = sub.add_parser("analyze")
    asub = ap.add_subparsers(dest="analyze_type", required=True)
    pa = asub.add_parser("pcap")
    pa.add_argument("pcap_path")
    pa.add_argument("-n", "--case", default="")
    ma = asub.add_parser("memory", aliases=["mem"])
    ma.add_argument("memory_dump")
    ma.add_argument("--profile", default="")
    ma.add_argument("-n", "--case", default="")
    ia = asub.add_parser("ioc", aliases=["iocs"])
    ia.add_argument("source", help="File path or inline text")
    ia.add_argument("-n", "--case", default="")
    ia.add_argument("--type", choices=["auto", "file", "text"], default="auto")
    ia.add_argument("--no-hash", action="store_true")
    ia.add_argument("-o", "--output", default="")

    # workflow
    wp = sub.add_parser("workflow")
    ws = wp.add_subparsers(dest="workflow_action", required=True)
    wr = ws.add_parser("run")
    wr.add_argument("file", help="Path to workflow JSON file")
    wr.add_argument("-v", "--verbose", action="store_true")
    we = ws.add_parser("example")
    we.add_argument("name", choices=["web", "ctf", "malware", "recon"])

    # report
    rp = sub.add_parser("report")
    rp.add_argument("case")
    rp.add_argument("--format", choices=["json", "text", "html"], default="text")
    rp.add_argument("-o", "--output", default="")

    # evidence
    ep = sub.add_parser("evidence")
    ep.add_argument("case")
    ep.add_argument("action", choices=["list", "add"])
    ep.add_argument("--file", default="")
    ep.add_argument("--type", default="raw")

    return p


def cmd_case(args, cm):
    if args.case_action == "create":
        c = cm.create(args.name, args.description, args.investigators)
        cprint(f"  Name: {c.name} | Status: {c.status}", "green")
    elif args.case_action == "list":
        for c in cm.list_cases():
            cprint(f"  {c['name']:<30} {c['status']:<10} {c['created'][:19]}", "gray")
    elif args.case_action == "close":
        cm.close_case(args.name)
    elif args.case_action == "reopen":
        cm.reopen_case(args.name)
    elif args.case_action == "delete":
        cm.delete_case(args.name)


def _save_result(result, out_path, cm, case_name, ev_type, summary):
    """Common helper: save result to file + attach to case if given."""
    if out_path:
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        cprint(f"[+] Results saved to {out_path}", "gray")
    if case_name:
        cm.add_evidence(case_name, {
            "type": ev_type, "summary": summary,
            "file_path": out_path or "",
        })
        cprint(f"[+] Attached to case '{case_name}'", "green")


def cmd_scan(args, cm, config):
    s = NmapScanner(nmap_binary=config.get("nmap_binary"), verbose=args.verbose)
    r = s.scan(args.target, ports=args.ports, args=args.args, sudo=args.sudo, timeout=args.timeout)
    cprint(f"\n[+] {s.summarize(r)}", "green")
    _save_result(r, args.output, cm, args.case, "nmap_scan", s.summarize(r))


def cmd_portscan(args, cm):
    s = PortScanner(timeout=args.timeout, verbose=args.verbose)
    r = s.scan(args.target, ports=args.ports, threads=args.threads, banner_grab=args.banner)
    cprint(f"\n[+] {s.summarize(r)}", "green")
    _save_result(r, args.output, cm, args.case, "portscan", s.summarize(r))


def cmd_http(args, cm):
    s = HttpScanner(verbose=args.verbose)
    r = s.scan(args.target)
    cprint(f"\n[+] {s.summarize(r)}", "green")
    if "hosts" in r and r["hosts"]:
        http = r["hosts"][0].get("http", {})
        if http.get("missing_headers"):
            cprint(f"  [!] Missing security headers: {', '.join(http['missing_headers'])}", "yellow")
        if http.get("waf"):
            cprint(f"  [*] WAF detected: {http['waf']}", "cyan")
        if http.get("technologies"):
            cprint(f"  [*] Technologies: {', '.join(http['technologies'])}", "cyan")
    _save_result(r, args.output, cm, args.case, "http_scan", s.summarize(r))


def cmd_subdomain(args, cm):
    s = SubdomainEnumerator(verbose=args.verbose)
    r = s.scan(
        args.target, threads=args.threads,
        use_crtsh=not args.no_crtsh,
        wordlist=open(args.wordlist).read().splitlines() if args.wordlist else None,
    )
    cprint(f"\n[+] {s.summarize(r)}", "green")
    _save_result(r, args.output, cm, args.case, "subdomain_enum", s.summarize(r))


def cmd_analyze(args, cm):
    if args.analyze_type == "pcap":
        a = PcapAnalyzer()
        if not a.available:
            cprint("[!] Install: sudo apt install tshark", "red")
            return
        r = a.analyze(args.pcap_path)
        cprint(f"\n[+] {a.summarize(r)}", "green")
        cm.evidence_dir(args.case) if args.case else None
        _save_result(r, "", cm, args.case, "pcap_analysis", a.summarize(r))
    elif args.analyze_type in ("memory", "mem"):
        a = VolatilityAnalyzer()
        if not a.available:
            cprint("[!] Install: pip install volatility3", "red")
            return
        r = a.analyze(args.memory_dump, profile=args.profile)
        cprint(f"\n[+] {a.summarize(r)}", "green")
        _save_result(r, "", cm, args.case, "memory_analysis", a.summarize(r))
    elif args.analyze_type in ("ioc", "iocs"):
        h = IOCHarvester(verbose=args.verbose)
        r = h.extract(args.source, source_type=args.type, compute_file_hashes=not args.no_hash)
        cprint(f"\n[+] {h.summarize(r)}", "green")
        s = r.get("stats", {})
        if s.get("urls"):
            cprint(f"  URLs: {', '.join(r['urls'][:5])}{'...' if len(r['urls'])>5 else ''}", "gray")
        if s.get("ipv4"):
            cprint(f"  IPs: {', '.join(r['ipv4'][:5])}{'...' if len(r['ipv4'])>5 else ''}", "gray")
        if s.get("emails"):
            cprint(f"  Emails: {', '.join(r['emails'][:5])}", "gray")
        if s.get("cves"):
            cprint(f"  CVEs: {', '.join(r['cves'])}", "yellow")
        _save_result(r, args.output, cm, args.case, "ioc_extraction", h.summarize(r))


def cmd_workflow(args, cm):
    if args.workflow_action == "run":
        try:
            wf = Workflow.load(args.file)
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            cprint(f"[!] Failed to load workflow: {e}", "red")
            return
        runner = WorkflowRunner(wf, case_manager=cm, verbose=args.verbose)
        runner.run()
    elif args.workflow_action == "example":
        wf = _build_example_workflow(args.name)
        out = f"/tmp/{args.name}_workflow.json"
        wf.save(out)
        cprint(f"  Edit and run: investigator workflow run {out}", "gray")


def _build_example_workflow(name):
    """Pre-built workflow templates for common scenarios."""
    if name == "web":
        return (Workflow("web_recon", "Web application reconnaissance pipeline")
                .add("subdomain", "subdomain", {"target": "TARGET"})
                .add("http", "http", {"target": "https://TARGET"})
                .add("nmap", "nmap", {"target": "TARGET", "ports": "80,443,8080,8443", "args": "-sV -sC -T4"})
                .add("ioc", "ioc", {"source": "/var/log/apache2/access.log"}))
    if name == "ctf":
        return (Workflow("ctf_box", "CTF box initial enumeration")
                .add("portscan", "portscan", {"target": "TARGET", "ports": "1-65535", "threads": 200, "banner": True})
                .add("nmap", "nmap", {"target": "TARGET", "args": "-sV -sC -A -T4 -p-"}))
    if name == "malware":
        return (Workflow("malware_triage", "Malware sample triage")
                .add("ioc", "ioc", {"source": "TARGET"})
                .add("memory", "memory", {"memory_dump": "TARGET"}))
    if name == "recon":
        return (Workflow("full_recon", "Full external recon")
                .add("subdomain", "subdomain", {"target": "TARGET"})
                .add("nmap", "nmap", {"target": "TARGET", "args": "-sn"})
                .add("http", "http", {"target": "https://TARGET"}))
    return Workflow(name)


def cmd_report(args, cm):
    case = cm.load(args.case)
    if not case:
        cprint(f"[!] Case '{args.case}' not found", "red")
        return
    out = args.output or f"{case.name.replace(' ', '_')}_report.{'txt' if args.format == 'text' else args.format}"
    if args.format == "json":
        ReportGenerator.generate_json(case, output_path=out)
    elif args.format == "html":
        with open(out, "w") as f:
            f.write(ReportGenerator.generate_html(case))
        cprint(f"[+] HTML report saved to {out}", "green")
    else:
        with open(out, "w") as f:
            f.write(ReportGenerator.generate_text(case))
        cprint(f"[+] Text report saved to {out}", "green")


def cmd_evidence(args, cm):
    case = cm.load(args.case)
    if not case:
        cprint(f"[!] Case '{args.case}' not found", "red")
        return
    locker = EvidenceLocker(cm.evidence_dir(args.case))
    if args.action == "list":
        for it in locker.list_evidence():
            cprint(f"  {it['name']:<50} {it['size']:<12} {it['modified'][:19]}", "gray")
    elif args.action == "add":
        if not args.file:
            cprint("[!] Use --file", "red")
            return
        result = locker.store_file(args.file, evidence_type=args.type)
        if "error" in result:
            cprint(f"[!] {result['error']}", "red")
            return
        cm.add_evidence(
            args.case,
            {"type": args.type, "source": args.file, "summary": f"Added {result['stored_name']}"},
        )
        cprint("[+] Evidence added", "green")


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = Config()
    cm = CaseManager(config)

    if args.command == "dashboard":
        from .dashboard import run_dashboard
        try:
            run_dashboard()
        except (KeyboardInterrupt, EOFError):
            print()
            cprint("[!] Dashboard closed", "yellow")
        return

    try:
        if args.command == "case":
            cmd_case(args, cm)
        elif args.command == "scan":
            cmd_scan(args, cm, config)
        elif args.command == "portscan":
            cmd_portscan(args, cm)
        elif args.command == "http":
            cmd_http(args, cm)
        elif args.command == "subdomain":
            cmd_subdomain(args, cm)
        elif args.command == "analyze":
            cmd_analyze(args, cm)
        elif args.command == "workflow":
            cmd_workflow(args, cm)
        elif args.command == "report":
            cmd_report(args, cm)
        elif args.command == "evidence":
            cmd_evidence(args, cm)
    except KeyboardInterrupt:
        cprint("\n[!] Interrupted", "yellow")
        sys.exit(1)
    except Exception as e:
        cprint(f"[!] Error: {e}", "red")
        if config.get("verbose"):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()


