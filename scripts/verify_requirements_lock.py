"""Fail when an exact direct dependency pin is absent from the reviewed lock."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
PIN_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")


def canonical_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(path):
    pins = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        match = PIN_PATTERN.match(raw_line.strip())
        if match:
            pins[canonical_name(match.group(1))] = match.group(2)
    return pins


def main():
    direct = read_pins(ROOT / "requirements.txt")
    locked = read_pins(ROOT / "requirements.lock")
    mismatches = [
        f"{name}: requirements.txt={version}, requirements.lock={locked.get(name, 'missing')}"
        for name, version in sorted(direct.items())
        if locked.get(name) != version
    ]
    if mismatches:
        print("Direct dependency pins do not match requirements.lock:", file=sys.stderr)
        print("\n".join(f"- {item}" for item in mismatches), file=sys.stderr)
        print("Regenerate and review requirements.lock before merging.", file=sys.stderr)
        return 1
    print(f"Verified {len(direct)} direct dependency pins against requirements.lock.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
