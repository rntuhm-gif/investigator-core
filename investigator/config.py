"""Global configuration for investigator."""
import json
from pathlib import Path

DEFAULT_CASE_DIR = Path.home() / ".investigator" / "cases"
DEFAULT_CONFIG_PATH = Path.home() / ".investigator" / "config.json"
DEFAULTS = {
    "case_dir": str(DEFAULT_CASE_DIR),
    "nmap_binary": "nmap",
    "nmap_timeout": 300,
    "nmap_default_args": "-sV -sC -T4",
    "verbose": False,
    "auto_open_report": False,
}


class Config:
    def __init__(self, path=None):
        self.path = path or DEFAULT_CONFIG_PATH
        self.data = dict(DEFAULTS)
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                with open(self.path) as f:
                    self.data.update(json.load(f))
            except (json.JSONDecodeError, OSError):
                pass

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

