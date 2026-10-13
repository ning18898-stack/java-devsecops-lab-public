"""Install the pinned official Temurin JDK locally without changing system settings."""

import hashlib
import logging
import platform
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".tools"
VERSION = "17.0.20.1_1"
ASSET = f"OpenJDK17U-jdk_x64_windows_hotspot_{VERSION}.zip"
URL = "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/" + ASSET


def fetch(url, destination):
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "java-devsecops-lab"})
            with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
            return
        except Exception:
            logging.warning("Download attempt %s failed", attempt)
            if attempt == 3:
                raise
            time.sleep(2)


def main():
    (ROOT / "artifacts").mkdir(exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(),
                                  logging.FileHandler(ROOT / "artifacts/setup-jdk.log", encoding="utf-8")])
    logging.info("Starting local JDK setup")
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("This helper supports Windows x64; use a Temurin 17 JDK on Ubuntu")
    TOOLS.mkdir(exist_ok=True)
    archive = TOOLS / ASSET
    checksum_file = TOOLS / (ASSET + ".sha256.txt")
    if not checksum_file.exists():
        fetch(URL + ".sha256.txt", checksum_file)
    expected = checksum_file.read_text().split()[0].lower()
    verified = False
    if archive.exists():
        with archive.open("rb") as stream:
            verified = hashlib.file_digest(stream, "sha256").hexdigest() == expected
    if not verified:
        partial = TOOLS / (ASSET + ".part")
        fetch(URL, partial)
        with partial.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise RuntimeError("Official SHA-256 verification failed")
        partial.replace(archive)
    logging.info("Official archive SHA-256 verified: %s", expected)
    destination = TOOLS / "jdk17"
    if not (destination / "jdk-17.0.20.1+1/bin/java.exe").exists():
        destination.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                if not (destination / member.filename).resolve().is_relative_to(destination.resolve()):
                    raise RuntimeError("Archive path outside local JDK directory")
            bundle.extractall(destination)
    java = destination / "jdk-17.0.20.1+1/bin/java.exe"
    result = subprocess.run([str(java), "-version"], capture_output=True, text=True, check=True)
    logging.info("%s", result.stderr.strip())
    logging.info("JAVA_HOME for this shell: %s", java.parent.parent)
    logging.info("Completed local JDK setup; exit code 0")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        logging.error("Local JDK setup failed: %s; exit code 1", error)
        sys.exit(1)
