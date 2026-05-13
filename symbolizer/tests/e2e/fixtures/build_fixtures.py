#!/usr/bin/env python3
"""Build E2E fixture ELF binaries and generate manifest.json.

Compiles C fixtures with gcc, then uses pyelftools to extract:
  - GNU build ID (from .note.gnu.build-id)
  - Symbol file offsets (vaddr → file_offset via PT_LOAD mapping)
  - Source file/line via addr2line (subprocess)

Usage:
    python3 build_fixtures.py          # rebuild all fixtures
    python3 build_fixtures.py --check  # verify manifest matches binaries

Dependencies: gcc, pyelftools (pip install pyelftools), addr2line
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

# ── Configuration ────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR / "src"
BIN_DIR = SCRIPT_DIR / "bin"
MANIFEST = SCRIPT_DIR / "manifest.json"

# Compiler flags: static, debug info, no optimization, frame pointers, build-id.
CFLAGS = ["-g", "-O0", "-static", "-fno-omit-frame-pointer", "-Wl,--build-id"]

# Fixture definitions: (name, source_file, [symbols_to_extract])
FIXTURES = [
    ("hello", "hello.c", ["target_function", "outer_call", "main"]),
    ("multi_dso", "multi_dso.c", ["compute_checksum", "process_packet", "main"]),
]


# ── ELF helpers ──────────────────────────────────────────────────────


def extract_build_id(elf: ELFFile) -> str:
    """Extract the GNU build ID as a hex string."""
    for section in elf.iter_sections():
        if section.name == ".note.gnu.build-id":
            for note in section.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    return note["n_desc"]
    raise ValueError("no GNU build ID found")


def find_symbol_vaddr(elf: ELFFile, name: str) -> int:
    """Find a FUNC symbol's virtual address in .symtab."""
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        symbols = section.get_symbol_by_name(name)
        if symbols:
            sym = symbols[0]
            if sym["st_info"]["type"] == "STT_FUNC":
                return sym["st_value"]
    raise ValueError(f"symbol '{name}' not found in .symtab")


def vaddr_to_file_offset(elf: ELFFile, vaddr: int) -> int:
    """Translate a virtual address to a file offset via PT_LOAD segments."""
    for segment in elf.iter_segments():
        if segment.header["p_type"] != "PT_LOAD":
            continue
        seg_start = segment.header["p_vaddr"]
        seg_end = seg_start + segment.header["p_filesz"]
        if seg_start <= vaddr < seg_end:
            return vaddr - seg_start + segment.header["p_offset"]
    raise ValueError(f"no PT_LOAD segment contains vaddr 0x{vaddr:x}")


def symbol_file_offset(elf: ELFFile, name: str) -> int:
    """Get the file offset for a named symbol."""
    vaddr = find_symbol_vaddr(elf, name)
    return vaddr_to_file_offset(elf, vaddr)


# ── Source location via addr2line ────────────────────────────────────


@dataclass
class SourceLocation:
    file: str
    line: int


def addr2line(elf_path: Path, vaddr: int) -> SourceLocation:
    """Get source file:line for a virtual address using addr2line."""
    result = subprocess.run(
        ["addr2line", "-e", str(elf_path), f"0x{vaddr:x}"],
        capture_output=True,
        text=True,
    )
    loc = result.stdout.strip()
    if ":" not in loc or loc.startswith("??"):
        return SourceLocation(file="??", line=0)

    file_path, line_str = loc.rsplit(":", 1)
    return SourceLocation(
        file=os.path.basename(file_path),
        line=int(line_str),
    )


# ── Build & manifest generation ─────────────────────────────────────


def compile_fixture(name: str, source: str) -> Path:
    """Compile a fixture C source to a static binary."""
    src_file = SRC_DIR / source
    elf_file = BIN_DIR / name

    if not src_file.exists():
        raise FileNotFoundError(f"source not found: {src_file}")

    subprocess.run(
        ["gcc", *CFLAGS, "-o", str(elf_file), str(src_file)],
        check=True,
    )
    return elf_file


def process_fixture(
    name: str, source: str, symbol_names: list[str]
) -> dict:
    """Compile a fixture and extract its manifest entry."""
    print(f"  Compiling {name} from {source}...")
    elf_path = compile_fixture(name, source)

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        build_id = extract_build_id(elf)
        print(f"    build_id: {build_id}")

        symbols = {}
        for sym_name in symbol_names:
            vaddr = find_symbol_vaddr(elf, sym_name)
            offset = vaddr_to_file_offset(elf, vaddr)
            loc = addr2line(elf_path, vaddr)
            symbols[sym_name] = {
                "file_offset": offset,
                "file": loc.file,
                "line": loc.line,
            }
            print(f"    {sym_name}: file_offset={offset} ({loc.file}:{loc.line})")

    return {"build_id_hex": build_id, "symbols": symbols}


# ── Check mode ───────────────────────────────────────────────────────


def check_fixtures() -> bool:
    """Verify that committed binaries match the manifest."""
    if not MANIFEST.exists():
        print("ERROR: manifest.json not found", file=sys.stderr)
        return False

    with open(MANIFEST) as f:
        manifest = json.load(f)

    ok = True
    for name, source, _ in FIXTURES:
        elf_path = BIN_DIR / name
        if not elf_path.exists():
            print(f"ERROR: binary not found: {elf_path}", file=sys.stderr)
            ok = False
            continue

        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            actual_bid = extract_build_id(elf)

        expected_bid = manifest.get(name, {}).get("build_id_hex", "")
        if actual_bid != expected_bid:
            print(
                f"ERROR: build_id mismatch for {name}: "
                f"manifest={expected_bid} actual={actual_bid}",
                file=sys.stderr,
            )
            ok = False
        else:
            print(f"  ✓ {name} build_id matches")

    if ok:
        print("All fixtures verified.")
    return ok


# ── Main ─────────────────────────────────────────────────────────────


def main():
    if "--check" in sys.argv:
        sys.exit(0 if check_fixtures() else 1)

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    print("Compiling fixtures...")

    manifest = {}
    for name, source, symbols in FIXTURES:
        manifest[name] = process_fixture(name, source, symbols)

    with open(MANIFEST, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print()
    print(f"Fixtures built:")
    print(f"  Binaries: {BIN_DIR}/")
    print(f"  Manifest: {MANIFEST}")
    print()
    print("Commit these files to the repo. Rebuild only when adding new test functions.")


if __name__ == "__main__":
    main()
