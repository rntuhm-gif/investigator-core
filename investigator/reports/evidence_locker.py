"""Store evidence files per case."""
import shutil
from datetime import datetime, timezone
from pathlib import Path


class EvidenceLocker:
    def __init__(self, case_dir):
        self.case_dir = Path(case_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)

    def store_file(self, source_path, evidence_type="raw"):
        src = Path(source_path)
        if not src.exists():
            return {"error": f"File not found: {source_path}"}
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dest = self.case_dir / f"{ts}_{evidence_type}_{src.name}"
        shutil.copy2(src, dest)
        return {
            "type": evidence_type,
            "original_name": src.name,
            "stored_name": dest.name,
            "path": str(dest),
            "size_bytes": dest.stat().st_size,
        }

    def store_text(self, content, filename, evidence_type="note"):
        dest = self.case_dir / filename
        with open(dest, "w") as f:
            f.write(content)
        return {
            "type": evidence_type,
            "stored_name": filename,
            "path": str(dest),
            "size_bytes": dest.stat().st_size,
        }

    def list_evidence(self):
        items = []
        for f in sorted(self.case_dir.iterdir()):
            if f.is_file():
                items.append({
                    "name": f.name,
                    "size": f.stat().st_size,
                    "modified": datetime.fromtimestamp(
                        f.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                })
        return items

