#!/usr/bin/env python3
"""
Validate that every chapter listed in docs/_quarto.yml exists on disk.

Run via: make docs-check
Exit 1 if any chapter file is missing, so CI and local `make ci` both catch
the error before Quarto tries to render a missing file.
"""

import re
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
QUARTO_YML = WORKSPACE_ROOT / "docs" / "_quarto.yml"
DOCS_DIR = WORKSPACE_ROOT / "docs"


def main() -> None:
    if not QUARTO_YML.exists():
        print(f"ERROR: {QUARTO_YML} not found.", file=sys.stderr)
        sys.exit(1)

    yml = QUARTO_YML.read_text()
    chapters = re.findall(r"^\s*-\s*(\S+\.qmd)", yml, re.MULTILINE)

    if not chapters:
        print("WARNING: no .qmd chapters found in _quarto.yml — is the file correct?")
        sys.exit(1)

    missing = [c for c in chapters if not (DOCS_DIR / c).exists()]

    if missing:
        print("ERROR: chapter(s) listed in docs/_quarto.yml but not found on disk:")
        for c in missing:
            print(f"  docs/{c}")
        print()
        print("Fix: run the doc generator or create placeholder files:")
        for c in missing:
            print(f"  touch docs/{c}")
        sys.exit(1)

    print(f"docs-check: all {len(chapters)} chapter(s) present.")


if __name__ == "__main__":
    main()
