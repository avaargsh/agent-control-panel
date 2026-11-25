"""Syntax-only regression guard for the two checked-in JetStream POC guides."""
import os
from pathlib import Path
import re
import subprocess
import sys


def check_document(text, name, required=()):
    errors, commands, headings = [], [], set()
    fence = None
    lines = []
    for number, line in enumerate(text.splitlines(), 1):
        if fence is None:
            match = re.fullmatch(r"(`{3,})([A-Za-z0-9_-]*)\s*", line)
            if match:
                fence = (len(match[1]), match[2], number)
                lines = []
            elif line.startswith("## "):
                if line in headings:
                    errors.append(f"{name}:{number}: duplicate section")
                headings.add(line)
        elif re.fullmatch(r"`{" + str(fence[0]) + r",}\s*", line):
            if fence[1] in {"sh", "bash", "shell"}:
                commands.extend(s.strip() for s in lines)
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-n"],
                    input="\n".join(lines) + "\n", text=True,
                    capture_output=True, timeout=5,
                    env={"PATH": os.defpath, "LC_ALL": "C"},
                )
                if result.returncode:
                    errors.append(f"{name}:{fence[2]}: shell syntax error")
            fence = None
        else:
            lines.append(line)
    if fence is not None:
        errors.append(f"{name}:{fence[2]}: unclosed fence")
    for command in required:
        if commands.count(command) != 1:
            errors.append(f"{name}: required command missing or repeated: {command}")
    return errors


def main():
    root = Path(__file__).resolve().parents[1] / "experiments/jetstream-poc"
    guides = {
        "LOCAL-REPRO.md": ("bash experiments/jetstream-poc/run-local.sh",),
        "DISPOSITION-INSPECTION.md": (
            "go test -race -count=1 -v -run '^TestRealDispositionInspectionIsReadOnlyAndDistinguishesEvidence$' .",
            "go test -race -count=1 -v -run '^TestRealDispositionInspectorWithRestrictedRoleAndAmbiguousPublish$' .",
            "go test -race -count=1 -v -run '^TestDispositionInspectCLI' .",
        ),
    }
    errors = []
    for name, required in guides.items():
        errors.extend(check_document((root / name).read_text(encoding="utf-8"), name, required))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("JETSTREAM_DOCS_SYNTAX_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
