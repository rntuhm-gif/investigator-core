"""Interactive TUI dashboard — list cases, browse findings, view evidence."""
import os
import sys
from ..case_manager import CaseManager
from ..utils.color_out import cprint


def run_dashboard():
    """Simple menu-driven dashboard for browsing cases and evidence."""
    cm = CaseManager()

    while True:
        os.system("clear" if os.name == "posix" else "cls")
        cprint("╔════════════════════════════════════════════════╗", "cyan")
        cprint("║         INVESTIGATOR-CORE DASHBOARD           ║", "cyan")
        cprint("╚════════════════════════════════════════════════╝", "cyan")
        print()
        cprint("  [1] List cases", "white")
        cprint("  [2] View case details", "white")
        cprint("  [3] Create new case", "white")
        cprint("  [4] List all evidence across cases", "white")
        cprint("  [5] Open case evidence directory", "white")
        cprint("  [6] Quick scan (with case)", "white")
        cprint("  [0] Exit", "white")
        print()

        choice = input("  Select: ").strip()

        if choice == "1":
            _list_cases(cm)
        elif choice == "2":
            _view_case(cm)
        elif choice == "3":
            _create_case(cm)
        elif choice == "4":
            _list_all_evidence(cm)
        elif choice == "5":
            _open_evidence_dir(cm)
        elif choice == "6":
            _quick_scan(cm)
        elif choice == "0":
            cprint("\n  Bye.\n", "cyan")
            return
        else:
            cprint("  [!] Invalid option", "yellow")

        input("\n  Press Enter to continue...")


def _list_cases(cm):
    cprint("\n  ── Cases ──", "cyan")
    cases = cm.list_cases()
    if not cases:
        cprint("  No cases yet.", "yellow")
        return
    print()
    cprint(f"  {'NAME':<30} {'STATUS':<10} {'EVIDENCE':<10} {'CREATED'}", "bold")
    print("  " + "─" * 75)
    for c in cases:
        cprint(f"  {c['name']:<30} {c['status']:<10} {c['evidence_count']:<10} {c['created'][:19]}")


def _view_case(cm):
    name = input("\n  Case name: ").strip()
    case = cm.load(name)
    if not case:
        cprint(f"  [!] Case '{name}' not found", "red")
        return
    d = case.to_dict()
    cprint(f"\n  ── Case: {d['name']} ──", "cyan")
    cprint(f"  Description: {d.get('description', '')}", "white")
    cprint(f"  Status: {d.get('status', 'unknown')}", "yellow")
    cprint(f"  Investigators: {', '.join(d.get('investigators', [])) or 'none'}", "white")
    cprint(f"  Created: {d.get('created_at', '')}", "gray")
    cprint(f"  Updated: {d.get('updated_at', '')}", "gray")
    cprint(f"\n  Evidence: {len(d.get('evidence', []))} item(s)", "cyan")
    for i, e in enumerate(d.get("evidence", []), 1):
        cprint(f"    {i}. [{e.get('type', '?')}] {e.get('source', 'N/A')[:60]}", "white")
        cprint(f"       {e.get('summary', '')}", "gray")
    cprint(f"\n  Findings: {len(d.get('findings', []))} item(s)", "cyan")
    for i, f in enumerate(d.get("findings", []), 1):
        cprint(f"    {i}. {f.get('summary', '')}", "white")


def _create_case(cm):
    name = input("\n  Case name: ").strip()
    if not name:
        return
    desc = input("  Description: ").strip()
    invs = input("  Investigators (comma-separated): ").strip()
    invs_list = [i.strip() for i in invs.split(",") if i.strip()] if invs else []
    try:
        cm.create(name, desc, invs_list)
    except FileExistsError as e:
        cprint(f"  [!] {e}", "red")


def _list_all_evidence(cm):
    cprint("\n  ── All Evidence ──", "cyan")
    cases = cm.list_cases()
    if not cases:
        cprint("  No cases.", "yellow")
        return
    for c in cases:
        case = cm.load(c["name"])
        if not case:
            continue
        ev = case.to_dict().get("evidence", [])
        if not ev:
            continue
        cprint(f"\n  [{c['name']}] {len(ev)} item(s):", "yellow")
        for i, e in enumerate(ev, 1):
            cprint(f"    {i}. [{e.get('type', '?')}] {e.get('source', 'N/A')[:70]}", "white")


def _open_evidence_dir(cm):
    name = input("\n  Case name: ").strip()
    d = cm.evidence_dir(name)
    cprint(f"  Evidence dir: {d}", "cyan")
    items = sorted(d.iterdir()) if d.exists() else []
    if not items:
        cprint("  (empty)", "yellow")
        return
    for f in items:
        if f.is_file():
            cprint(f"    {f.name} ({f.stat().st_size} bytes)", "white")


def _quick_scan(cm):
    target = input("\n  Target (IP/host): ").strip()
    if not target:
        return
    case = input("  Case name (empty to skip): ").strip()
    if case:
        if not cm.load(case):
            cm.create(case, description=f"Auto-created for {target}")
        cmd = f"investigator scan {target} -n \"{case}\" -p- 2>&1 | tail -20"
    else:
        cmd = f"investigator scan {target} -p- 2>&1 | tail -20"
    cprint(f"\n  Running: {cmd}", "gray")
    os.system(cmd)

