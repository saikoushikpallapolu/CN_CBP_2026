"""Compatibility runner. The maintained backend tests live in tests/."""
if __name__ == "__main__":
    import subprocess
    import sys
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", "tests", "-q"]))
