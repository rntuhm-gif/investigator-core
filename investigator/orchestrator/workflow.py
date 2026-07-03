"""Workflow definition — declarative multi-step investigation pipelines.

A workflow is a list of Steps. Each step references a tool (scanner/analyzer)
and binds its results into the shared context object that subsequent steps
can read.
"""
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
from ..utils.color_out import cprint


@dataclass
class Step:
    name: str
    tool: str           # e.g. "nmap", "portscan", "http", "subdomain", "ioc", "pcap"
    args: dict = field(default_factory=dict)
    bind: str = ""      # context key to store the result under (defaults to name)
    on_fail: str = "continue"   # "continue" | "stop" | "skip_remaining"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


@dataclass
class Workflow:
    name: str
    description: str = ""
    steps: list = field(default_factory=list)  # list[Step]
    target: str = ""
    case_name: str = ""

    def add(self, name, tool, args=None, bind="", on_fail="continue"):
        self.steps.append(Step(name=name, tool=tool, args=args or {}, bind=bind or name, on_fail=on_fail))
        return self

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "case_name": self.case_name,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d):
        wf = cls(
            name=d["name"],
            description=d.get("description", ""),
            target=d.get("target", ""),
            case_name=d.get("case_name", ""),
        )
        wf.steps = [Step.from_dict(s) for s in d.get("steps", [])]
        return wf

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        cprint(f"[+] Workflow saved: {path}", "green")

    @classmethod
    def load(cls, path):
        with open(path) as f:
            return cls.from_dict(json.load(f))

