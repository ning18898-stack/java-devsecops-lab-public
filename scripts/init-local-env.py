"""Generate isolated local database secrets; keep existing non-empty values."""

import logging
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("DB_PASSWORD", "MYSQL_ROOT_PASSWORD", "TEST_DB_PASSWORD", "MYSQL_TEST_ROOT_PASSWORD")


def main():
    (ROOT / "artifacts").mkdir(exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(
                            ROOT / "artifacts/init-local-env.log", encoding="utf-8")])
    logging.info("Starting local secret initialization")
    path = ROOT / ".env"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    existing = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            if key.strip() in NAMES:
                if key.strip() in existing:
                    raise ValueError("Duplicate database variable in .env")
                existing[key.strip()] = value.strip()
    missing = [name for name in NAMES if not existing.get(name)]
    if missing:
        lines = [line for line in lines if line.split("=", 1)[0].strip() not in missing]
        lines.extend(f"{name}={secrets.token_hex(24)}" for name in missing)
        temporary = ROOT / ".env.generated"
        temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
        temporary.replace(path)
        if sys.platform != "win32":
            path.chmod(0o600)
    logging.info("Generated %s missing values; existing values retained; exit code 0", len(missing))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        logging.error("Local secret initialization failed: %s; exit code 1", type(error).__name__)
        sys.exit(1)
