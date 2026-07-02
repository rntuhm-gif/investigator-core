"""investigator CLI — main entry point."""
import argparse
import json
import sys
from . import __version__
from .config import Config
from .case_manager import CaseManager
from .scanners import NmapScanner
from .analyzers import PcapAnalyzer, VolatilityAnalyzer
from .reports import ReportGenerator, EvidenceLocker
from .utils.color_out import cprint


def build_parser():
    p = argparse.ArgumentParser(
        prog="investigator",
        description="Multi-tool investigation orchestrator — Nmap, PCAP/memory forensics, case management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"investigator {__version__}")
    p.add_argument("--verbose", "-v", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

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

    # scan
    sp = sub.add_parser("scan")
    sp.add_argument("target")
    sp.add_argument("-n", "--case", default="")
    sp.add_argument("-p", "--ports", default="")
    sp.add_argument("--args", default="-sV -sC -T4")
    sp.add_argument("--sudo", action="store_true")
    sp.add_argument("--timeout", type=int, default=300)
    sp.add_argument("-o", "--output", default="")

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


def cmd_scan(args, cm, config):
    s = NmapScanner(nmap_binary=config.get("nmap_binary"), verbose=args.verbose)
    r = s.scan(args.target, ports=args.ports, args=args.args, sudo=args.sudo, timeout=args.timeout)
    cprint(f"\n[+] Scan complete: {s.summarize(r)}", "green")
    out = args.output
    if not out and args.case:
        out = str(cm.evidence_dir(args.case) / f"nmap_{args.target.replace('/', '_')}.json")
    if out:
        with open(out, "w") as f:
            json.dump(r, f, indent=2, default=str)
        cprint(f"[+] Results saved to {out}", "gray")
    if args.case:
        cm.add_evidence(
            args.case,
            {
                "type": "nmap_scan",
                "source": args.target,
                "summary": s.summarize(r),
                "file_path": out or "",
            },
        )
        cprint(f"[+] Attached to case '{args.case}'", "green")
    else:
        print(json.dumps(r, indent=2, default=str))


def cmd_analyze(args, cm):
    if args.analyze_type == "pcap":
        a = PcapAnalyzer()
        if not a.available:
            cprint("[!] Install: sudo apt install tshark", "red")
            return
        r = a.analyze(args.pcap_path)
        if args.case:
            cm.evidence_dir(args.case)
            cm.add_evidence(
                args.case,
                {
                    "type": "pcap_analysis",
                    "source": args.pcap_path,
                    "summary": a.summarize(r),
                },
            )
            cprint(f"[+] PCAP analysis attached to '{args.case}'", "green")
        else:
            cprint(f"[+] {a.summarize(r)}", "green")
            print(json.dumps(r, indent=2, default=str)[:2000])
    elif args.analyze_type in ("memory", "mem"):
        a = VolatilityAnalyzer()
        if not a.available:
            cprint("[!] Install: pip install volatility3", "red")
            return
        r = a.analyze(args.memory_dump, profile=args.profile)
        if args.case:
            cm.add_evidence(
                args.case,
                {
                    "type": "memory_analysis",
                    "source": args.memory_dump,
                    "summary": a.summarize(r),
                },
            )
            cprint(f"[+] Memory analysis attached to '{args.case}'", "green")
        else:
            cprint(f"[+] {a.summarize(r)}", "green")
            print(json.dumps(r, indent=2, default=str)[:2000])


def cmd_report(args, cm):
    case = cm.load(args.case)
    if not case:
        cprint(f"[!] Case '{args.case}' not found", "red")
        return
    out = args.output or f"{case.name.replace(' ', '_')}_report.{args.format}"
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
            {
                "type": args.type,
                "source": args.file,
                "summary": f"Added {result['stored_name']}",
            },
        )
        cprint("[+] Evidence added", "green")


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = Config()
    cm = CaseManager(config)
    try:
        if args.command == "case":
            cmd_case(args, cm)
        elif args.command == "scan":
            cmd_scan(args, cm, config)
        elif args.command == "analyze":
            cmd_analyze(args, cm)
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

