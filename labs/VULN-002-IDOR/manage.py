"""Start/stop only the dedicated VULN-002 container, retaining its volume."""
import sys
import db
import runtime as rt


def manage(action):
    if action == "up":
        db.credentials(True)
        prefix = ["docker", "compose", "--env-file", str(db.ROOT / ".env.vuln002"),
            "-f", str(db.LAB / "compose.yml")]
        rt.command([*prefix, "config", "--quiet"], "compose-config")
        rt.command([*prefix, "up", "-d", "--wait", "--wait-timeout", "180"], "compose-up", timeout=240)
        db.regression_database()
        db.isolation()
    elif action == "down":
        rt.command(["docker", "compose", "--env-file", str(db.ROOT / ".env.vuln002"),
            "-f", str(db.LAB / "compose.yml"), "down"], "compose-down")
    else:
        raise ValueError("Use up or down; volume reset is not provided")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Use up or down")
        manage(sys.argv[1])
    except Exception as error:
        print(f"VULN-002 setup FAIL {type(error).__name__}; exit code 1")
        sys.exit(1)
