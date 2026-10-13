"""Initialize only this lab's ignored local credentials; preserve existing values."""
import logging
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAMES = ("VULN001_DB_PASSWORD", "VULN001_ROOT_PASSWORD")

def main():
    (ROOT / "artifacts").mkdir(exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", handlers=[
        logging.StreamHandler(), logging.FileHandler(ROOT / "artifacts/vuln001-env.log", encoding="utf-8")])
    logging.info("Starting VULN-001 local credential initialization")
    path = ROOT / ".env.vuln001"
    lines = path.read_text().splitlines() if path.exists() else []
    values = {}
    for line in lines:
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            if key not in NAMES or key in values:
                raise ValueError("Unexpected or duplicate lab variable")
            values[key] = value
    generated = 0
    for name in NAMES:
        if not values.get(name):
            values[name] = secrets.token_hex(24)
            generated += 1
    temporary = ROOT / ".env.vuln001.generated"
    temporary.write_text("".join(f"{name}={values[name]}\n" for name in NAMES))
    temporary.replace(path)
    if sys.platform != "win32":
        path.chmod(0o600)
    logging.info("Generated %s missing values; exit code 0", generated)

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        logging.error("Initialization failed: %s; exit code 1", type(error).__name__)
        sys.exit(1)
