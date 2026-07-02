"""Case management — create, list, open, close, delete cases."""
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from .config import Config
from .utils.color_out import cprint


class Case:
    def __init__(self, name, description="", investigators=None):
        self.name = name
        self.description = description
        self.investigators = investigators or []
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at
        self.status = "open"
        self.evidence = []
        self.notes = []
        self.findings = []

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "investigators": self.investigators,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "evidence": self.evidence,
            "notes": self.notes,
            "findings": self.findings,
        }

    @classmethod
    def from_dict(cls, d):
        c = cls(d["name"], d.get("description", ""), d.get("investigators", []))
        c.created_at = d.get("created_at", c.created_at)
        c.updated_at = d.get("updated_at", c.updated_at)
        c.status = d.get("status", "open")
        c.evidence = d.get("evidence", [])
        c.notes = d.get("notes", [])
        c.findings = d.get("findings", [])
        return c


class CaseManager:
    def __init__(self, config=None):
        self.config = config or Config()
        self.case_dir = Path(self.config.get("case_dir"))
        self.case_dir.mkdir(parents=True, exist_ok=True)

    def _case_path(self, name):
        safe = "".join(c if c.isalnum() or c in "._- " else "_" for c in name).strip()
        return self.case_dir / f"{safe}.json"

    def create(self, name, description="", investigators=None):
        path = self._case_path(name)
        if path.exists():
            raise FileExistsError(f"Case '{name}' already exists")
        case = Case(name, description, investigators)
        ev_dir = self.case_dir / f"{path.stem}_evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        self._save(case)
        cprint(f"[+] Case '{name}' created", "green")
        return case

    def _save(self, case):
        path = self._case_path(case.name)
        case.updated_at = datetime.now(timezone.utc).isoformat()
        with open(path, "w") as f:
            json.dump(case.to_dict(), f, indent=2)

    def load(self, name):
        path = self._case_path(name)
        if not path.exists():
            return None
        with open(path) as f:
            return Case.from_dict(json.load(f))

    def list_cases(self):
        cases = []
        for fpath in sorted(self.case_dir.glob("*.json")):
            try:
                with open(fpath) as f:
                    d = json.load(f)
                cases.append({
                    "name": d.get("name", fpath.stem),
                    "status": d.get("status", "unknown"),
                    "description": d.get("description", ""),
                    "created": d.get("created_at", ""),
                    "evidence_count": len(d.get("evidence", [])),
                })
            except Exception:
                continue
        return cases

    def add_evidence(self, case_name, evidence_item):
        case = self.load(case_name)
        if not case:
            return False
        evidence_item["timestamp"] = datetime.now(timezone.utc).isoformat()
        case.evidence.append(evidence_item)
        self._save(case)
        return True

    def add_finding(self, case_name, finding):
        case = self.load(case_name)
        if not case:
            return False
        finding["timestamp"] = datetime.now(timezone.utc).isoformat()
        case.findings.append(finding)
        self._save(case)
        return True

    def close_case(self, name):
        case = self.load(name)
        if not case:
            return False
        case.status = "closed"
        self._save(case)
        cprint(f"[+] Case '{name}' closed", "yellow")
        return True

    def reopen_case(self, name):
        case = self.load(name)
        if not case:
            return False
        case.status = "open"
        self._save(case)
        cprint(f"[+] Case '{name}' reopened", "green")
        return True

    def delete_case(self, name):
        path = self._case_path(name)
        if not path.exists():
            return False
        ev_dir = self.case_dir / f"{path.stem}_evidence"
        if ev_dir.exists():
            shutil.rmtree(ev_dir)
        path.unlink()
        cprint(f"[+] Case '{name}' deleted", "red")
        return True

    def evidence_dir(self, case_name):
        path = self._case_path(case_name)
        d = self.case_dir / f"{path.stem}_evidence"
        d.mkdir(parents=True, exist_ok=True)
        return d

