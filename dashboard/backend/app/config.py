from dataclasses import dataclass
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "automation/src"))


@dataclass(frozen=True)
class Settings:
    database: Path
    imports: Path

    @classmethod
    def local(cls):
        return cls(Path(os.environ.get("DASHBOARD_DB", ROOT / "artifacts/dashboard/dashboard.sqlite3")),
                   Path(os.environ.get("DASHBOARD_IMPORT_ROOT", ROOT / "artifacts/phase4")))
