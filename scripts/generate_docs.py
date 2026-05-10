#!/usr/bin/env python3
"""
Bistouri Documentation Generator

Reads the Bistouri source code and generates per-module Quarto (.qmd) chapters
using Gemini. Designed for the free tier: chunked context per chapter
and rate-limited to 5 requests/minute.

Source paths are resolved dynamically via `cargo metadata` so the script stays
correct as the workspace evolves — no manual path updates required.

Usage:
    GEMINI_API_KEY=<key> python scripts/generate_docs.py
"""

import asyncio
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import google.genai as genai

# ── Configuration ────────────────────────────────────────────────────────────

MODEL = "gemini-3-flash-preview"
DOCS_DIR = Path("docs")
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
RATE_LIMIT_SECONDS = 12  # 5 requests/minute = 1 every 12 seconds

# Live documentation URLs — passed to the LLM for self-verification context
LIVE_DOCS_URLS = {
    "index.qmd": "https://sugarraysam.github.io/bistouri/",
    "trigger.qmd": "https://sugarraysam.github.io/bistouri/trigger.html",
    "profiler.qmd": "https://sugarraysam.github.io/bistouri/profiler.html",
    "ebpf.qmd": "https://sugarraysam.github.io/bistouri/ebpf.html",
    "symbolizer.qmd": "https://sugarraysam.github.io/bistouri/symbolizer.html",
}

# ── System prompt (sent with every call) ─────────────────────────────────────

SYSTEM_PROMPT = """\
You are a senior systems engineer writing a technical book about building an
eBPF-based profiling agent called Bistouri. Your audience is engineers who want
to understand the design — not the API surface.

WRITING PHILOSOPHY:
- Write like you are teaching a colleague over coffee. Use narrative prose, not
  bullet-point dumps. Each section should flow naturally into the next.
- Explain WHY decisions were made, not WHAT the code does. The reader has the
  code — they need the context the code cannot give them.
- Focus on: tradeoffs considered, algorithms chosen (and rejected), failure
  modes, performance implications, and design principles.
- DO NOT duplicate what belongs in docs.rs: no type signatures, no API
  listings, no field-by-field struct descriptions. If you catch yourself
  explaining a function signature, stop and ask what design insight that
  function reveals instead.
- If a section would just restate the code in English, delete it. Empty space
  is better than parroting source.
- Use code snippets ONLY to illustrate a design point — never to catalogue an
  implementation.
- A reader should finish each chapter able to explain the design to someone
  else without looking at the code.
- If a chapter is not interesting — if it does not teach something surprising
  or non-obvious — output only the YAML frontmatter with a comment:
  <!-- Nothing interesting to document here yet. -->

MERMAID DIAGRAM RULES:
- Use mermaid diagrams for data flow and state machines — they should clarify
  relationships that prose alone cannot.
- CRITICAL: Quarto requires mermaid blocks to use curly-brace syntax:
  ```{{mermaid}}
  graph TD
      A --> B
  ```
  Do NOT use ```mermaid (without curly braces) — it will NOT render.
- Valid diagram types: graph TD, graph LR, flowchart TD, flowchart LR,
  stateDiagram-v2, sequenceDiagram, classDiagram.
- DO NOT use "state_machine" — that is NOT a valid Mermaid keyword. Use
  "stateDiagram-v2" for state diagrams.
- ALWAYS quote node labels containing special characters (parentheses, slashes,
  brackets, dots, colons). Example: A["Label (with parens)"] not A[Label (with parens)]
- ALWAYS quote edge labels: A -->|"label text"| B
- Use subgraph titles with quotes: subgraph "My Group"
- Do NOT use double-curly-brace node shapes like {{{{text}}}} — they conflict
  with Quarto template syntax. Use ["text"] instead.
- Keep diagrams clean: max ~15 nodes, clear labels, logical grouping.
- Test mentally: would this parse as standard Mermaid JS syntax? If unsure, simplify.

AESTHETICS:
- These docs are publicly deployed and represent the project's professional quality.
- Use rich, descriptive section introductions that draw the reader in.
- Use Quarto callout blocks to highlight key insights:
  ::: {{.callout-tip}}
  ## Key Insight
  Explanation here.
  :::
  Valid types: .callout-note, .callout-tip, .callout-important, .callout-warning
- Prefer prose paragraphs over bullet lists. Bullets are acceptable for
  enumerating distinct items (e.g., map types) but narrative flow is preferred
  for explaining design reasoning.

STABILITY AND CONSERVATISM:
- Be conservative about changes. Documentation should evolve incrementally,
  not be rewritten from scratch each time.
- If you receive an existing chapter: preserve its tone, structure, and prose
  style. Only update what is factually stale or missing.
- If the code has not changed meaningfully since the last version, return the
  existing chapter UNCHANGED. Do not rephrase for the sake of rephrasing.
- Never reorganize sections. The skeleton is fixed.

LIVE DOCUMENTATION (your output becomes these pages):
- Landing:    {live_url_landing}
- Trigger:    {live_url_trigger}
- Profiler:   {live_url_profiler}
- eBPF:       {live_url_ebpf}
- Symbolizer: {live_url_symbolizer}

Your output will be rendered by Quarto and deployed to GitHub Pages. If anything
in the current live pages is broken (e.g. diagrams not rendering, placeholder
text, formatting issues), FIX IT in your output.

OUTPUT FORMAT:
1. Output ONLY valid Quarto Markdown (.qmd). No wrapping code fences.
   Do NOT wrap your output in ```qmd ... ``` or ```markdown ... ``` blocks.
   The raw output is written directly to a .qmd file.
2. Start with YAML frontmatter:
   ---
   title: "<chapter title>"
   ---
3. Follow the provided section skeleton EXACTLY — do not add, remove, or
   rename sections.
4. End the document with:
   ---
   _Auto-generated from commit `{commit_sha}` by Gemini 3.1 Pro.
   Last updated: {date}_
"""

# ── Per-chapter prompt templates ─────────────────────────────────────────────

FIRST_DRAFT_PROMPT = """\
Write the first draft of this chapter based on the source code below.
Remember: explain the design, tradeoffs, and algorithms — do NOT rewrite the
code in English. If a section has nothing interesting to say, keep it brief or
note that it will be expanded as the codebase evolves.

SECTION SKELETON (follow this structure exactly):
{skeleton}

SOURCE CODE:
{code_context}
"""

INCREMENTAL_PROMPT = """\
Below is the CURRENT version of this chapter and the CURRENT source code.

YOUR TASK:
- Review the existing chapter against the current code.
- Make ONLY the changes necessary to keep the documentation accurate and
  relevant.
- Preserve the tone, structure, and prose style of the existing chapter.
- If the code has not changed meaningfully, return the existing chapter
  UNCHANGED. Do not rephrase working prose.
- If new design decisions or tradeoffs have been introduced, add them
  naturally into the existing narrative.
- DO NOT rewrite sections that are still accurate just to sound different.
- DO NOT change the section skeleton.
- VERIFY that all mermaid diagrams use valid syntax (see system prompt rules).
  Fix any broken diagrams.

CURRENT CHAPTER:
{existing_chapter_content}

SECTION SKELETON (must match exactly):
{skeleton}

CURRENT SOURCE CODE:
{code_context}
"""

# ── Chapter definitions ───────────────────────────────────────────────────────
#
# Each source spec item is one of:
#
#   {"crate": "<name>"}
#       The entire <crate_src_root>/ directory — the primary form.
#       Any new module added to the crate is automatically included.
#
#   {"crate": "<name>", "rel": "<relative-path>"}
#       A path relative to the crate manifest directory (not src/).
#       Use only for assets that live outside src/ (e.g. proto/, build.rs).
#
#   "<string>"
#       A path relative to the workspace root (file or directory).
#       Use for cross-cutting files like AGENTS.md that belong to no crate.
#
# ── Why no "path" submodule filtering? ───────────────────────────────────────
#
# Filtering to a submodule (e.g. {"crate": "agent", "path": "trigger"}) is
# just a hardcoded path in disguise: add agent/src/scheduler/ and trigger.qmd
# silently misses it. Instead, each chapter draws from full crate source trees
# and uses its SKELETON to tell the LLM which subsystem to focus on. Modern
# LLMs have million-token context windows; agent/src/ is ~180 KB — trivial.
#
# The only time you should edit this file is to add a new chapter entry.
# New modules within existing crates appear in context automatically.

CHAPTERS = [
    {
        "filename": "index.qmd",
        "title": "Architecture & Design Philosophy",
        # The overview chapter needs all crates to paint the full picture,
        # plus workspace-level docs that capture design intent.
        "sources": [
            {"crate": "agent"},
            {"crate": "api"},
            {"crate": "api", "rel": "proto"},
            "AGENTS.md",
            "Cargo.toml",
        ],
        "skeleton": (
            """\
## What is Bistouri?
## Why eBPF for Profiling?
## Architecture at a Glance
## Component Map (use a ```{mermaid}``` flowchart)
## The Event Pipeline
## Design Principles
## Key Tradeoffs"""
        ),
    },
    {
        "filename": "trigger.qmd",
        "title": "Trigger Agent",
        # Full agent source: the LLM focuses on the trigger subsystem per the
        # skeleton. New modules under agent/src/ appear here automatically.
        "sources": [
            {"crate": "agent"},
        ],
        "skeleton": (
            """\
## The Problem: When to Profile?
## PSI as a Trigger Mechanism
## Trie-Based Process Routing
## Configuration Matching & Glob Semantics
## The proc_walk Loop
## Hot Reload Without Downtime
## Eventual Consistency Model
## Data Flow (use a ```{mermaid}``` diagram)"""
        ),
    },
    {
        "filename": "profiler.qmd",
        "title": "Profiler Agent",
        # Full agent source: the LLM focuses on the capture/profiling subsystem
        # per the skeleton. New modules under agent/src/ appear here automatically.
        "sources": [
            {"crate": "agent"},
        ],
        "skeleton": (
            """\
## From Trigger to Stack Trace
## BPF Map Lifecycle
## Ring Buffer vs Perf Buffer
## LPM Trie for Cgroup Matching
## Batch Updates & Performance
## Error Recovery
## Agent Lifecycle (use a ```{mermaid}``` stateDiagram-v2 — NOT state_machine)"""
        ),
    },
    {
        "filename": "ebpf.qmd",
        "title": "eBPF Programs",
        # Full agent source + build.rs outside src/: the LLM focuses on the
        # eBPF C programs, the libbpf-rs loader, and the build pipeline.
        "sources": [
            {"crate": "agent"},
            {"crate": "agent", "rel": "build.rs"},
        ],
        "skeleton": (
            """\
## eBPF in 5 Minutes
## The Profiler Program
## Shared Data Structures (Kernel ↔ Userspace)
## Satisfying the Verifier
## Build Pipeline (libbpf-cargo)
## Memory Layout & repr(C)
## Program Flow (use a ```{mermaid}``` diagram)"""
        ),
    },
    {
        "filename": "symbolizer.qmd",
        "title": "Symbolizer Service",
        # The symbolizer is early-stage; the LLM is instructed to note when a
        # section has nothing interesting to say yet.
        "sources": [
            {"crate": "symbolizer"},
            {"crate": "api"},
            {"crate": "api", "rel": "proto"},
        ],
        "skeleton": (
            """\
## The Cross-Host Symbolization Problem
## gRPC Interface & Protobuf Contract
## Symbol Resolution Pipeline
## Build ID Indexing
## Deployment Model
## Service Lifecycle (use a ```{mermaid}``` diagram)"""
        ),
    },
]

# ── Source file extensions to include ────────────────────────────────────────

SOURCE_EXTENSIONS = {".rs", ".c", ".h", ".toml", ".md", ".yml", ".yaml", ".proto"}


# ── Workspace discovery ───────────────────────────────────────────────────────


def discover_crates() -> dict[str, Path]:
    """Return a map of crate name → src/ root, discovered via cargo metadata.

    Using cargo metadata means crate paths are resolved the same way Cargo
    does, so renaming or restructuring workspace crates never breaks this
    script — only the chapter source specs (which are semantic, not structural)
    would need updating.
    """
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=True,
        cwd=WORKSPACE_ROOT,
    )
    meta = json.loads(result.stdout)
    # Strip the shared "bistouri-" package prefix so chapter source specs can
    # use the short crate name ("agent", "api", "symbolizer") instead of the
    # full package name. If the convention ever changes, update this prefix.
    prefix = "bistouri-"
    return {
        pkg["name"].removeprefix(prefix): Path(pkg["manifest_path"]).parent / "src"
        for pkg in meta["packages"]
    }


def _crate_root(crate_name: str, crate_map: dict[str, Path]) -> Path:
    """Return the manifest directory (parent of src/) for a crate."""
    return crate_map[crate_name].parent


# ── Helpers ───────────────────────────────────────────────────────────────────


def get_commit_sha() -> str:
    """Get the short SHA of the current HEAD commit."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=WORKSPACE_ROOT,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def read_sources(sources: list, crate_map: dict[str, Path]) -> str:
    """Resolve source specs and concatenate relevant files into a context string.

    Each spec is resolved to a path and then rglob-walked for supported
    extensions. Unknown crates or missing paths emit a warning and are skipped
    so that a missing stub never aborts the whole run.

    Spec forms:
        {"crate": "<name>"}              — entire crate src/ directory
        {"crate": "<name>", "rel": "x"}  — path relative to crate manifest dir
        "<string>"                       — path relative to workspace root
    """
    context = ""
    for spec in sources:
        if isinstance(spec, dict):
            crate_name = spec["crate"]
            if crate_name not in crate_map:
                print(
                    f"  ⚠  Unknown crate '{crate_name}' in chapter sources — skipping.",
                    file=sys.stderr,
                )
                continue

            if "rel" in spec:
                # Asset that lives outside src/ (e.g. proto/, build.rs)
                path = _crate_root(crate_name, crate_map) / spec["rel"]
            else:
                # Entire crate src/ — the standard form
                path = crate_map[crate_name]
        else:
            # Plain string → workspace-relative file or directory
            path = WORKSPACE_ROOT / spec

        if path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file() and f.suffix in SOURCE_EXTENSIONS:
                    rel = f.relative_to(WORKSPACE_ROOT)
                    context += f"\n--- File: {rel} ---\n{f.read_text()}\n"
        elif path.is_file():
            rel = path.relative_to(WORKSPACE_ROOT)
            context += f"\n--- File: {rel} ---\n{path.read_text()}\n"
        else:
            print(f"  ⚠  Source path not found: {path} — skipping.", file=sys.stderr)

    return context


def strip_wrapping_fences(text: str) -> str:
    """Strip markdown code fences that LLMs sometimes wrap their output in.

    Handles patterns like:
        ```qmd\\n...\\n```
        ```markdown\\n...\\n```
        ```\\n...\\n```
    """
    pattern = r"^\s*```(?:qmd|markdown|md)?\s*\n(.*?)```\s*$"
    match = re.match(pattern, text, re.DOTALL)
    if match:
        return match.group(1)
    return text


async def generate_chapter(
    client: genai.Client,
    chapter: dict,
    crate_map: dict[str, Path],
    commit_sha: str,
    date_str: str,
) -> None:
    """Generate or incrementally update a single .qmd chapter via Gemini."""
    code_context = read_sources(chapter["sources"], crate_map)
    output_path = DOCS_DIR / chapter["filename"]

    # Decide: incremental update or first draft
    existing_content = None
    if output_path.exists():
        content = output_path.read_text().strip()
        # Only treat as existing if it has real content (not just a placeholder)
        if (
            content
            and "# Placeholder" not in content
            and "will be generated by the documentation pipeline" not in content
        ):
            existing_content = content

    if existing_content is not None:
        user_prompt = INCREMENTAL_PROMPT.format(
            existing_chapter_content=existing_content,
            code_context=code_context,
            skeleton=chapter["skeleton"],
        )
    else:
        user_prompt = FIRST_DRAFT_PROMPT.format(
            code_context=code_context,
            skeleton=chapter["skeleton"],
        )

    system_instruction = SYSTEM_PROMPT.format(
        commit_sha=commit_sha,
        date=date_str,
        live_url_landing=LIVE_DOCS_URLS.get("index.qmd", "N/A"),
        live_url_trigger=LIVE_DOCS_URLS.get("trigger.qmd", "N/A"),
        live_url_profiler=LIVE_DOCS_URLS.get("profiler.qmd", "N/A"),
        live_url_ebpf=LIVE_DOCS_URLS.get("ebpf.qmd", "N/A"),
        live_url_symbolizer=LIVE_DOCS_URLS.get("symbolizer.qmd", "N/A"),
    )

    response = await client.aio.models.generate_content(
        model=MODEL,
        contents=user_prompt,
        config=genai.types.GenerateContentConfig(
            system_instruction=system_instruction,
        ),
    )

    # Post-process: strip any wrapping code fences from LLM output
    cleaned = strip_wrapping_fences(response.text)

    output_path.write_text(cleaned)
    print(f"  ✓ {chapter['filename']}")


async def main() -> None:
    """Generate all documentation chapters."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(
            "ERROR: GEMINI_API_KEY environment variable is not set.",
            file=sys.stderr,
        )
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    print("Discovering workspace crates via cargo metadata...")
    try:
        crate_map = discover_crates()
    except subprocess.CalledProcessError as e:
        print(f"ERROR: cargo metadata failed:\n{e.stderr}", file=sys.stderr)
        sys.exit(1)

    for name, src in sorted(crate_map.items()):
        print(f"  {name}: {src}")

    commit_sha = get_commit_sha()
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    DOCS_DIR.mkdir(exist_ok=True)

    print(f"\nGenerating docs from commit {commit_sha} ({date_str})")
    print(f"Model: {MODEL}")
    print(f"Rate limit: {RATE_LIMIT_SECONDS}s between calls\n")

    for i, chapter in enumerate(CHAPTERS):
        # Rate limit: async sleep between calls (skip before the first one)
        if i > 0:
            print(f"  ⏳ Rate limiting ({RATE_LIMIT_SECONDS}s)...")
            await asyncio.sleep(RATE_LIMIT_SECONDS)

        print(f"  Generating {chapter['filename']}...")
        try:
            await generate_chapter(client, chapter, crate_map, commit_sha, date_str)
        except Exception as e:
            print(f"  ✗ {chapter['filename']}: {e}", file=sys.stderr)
            # Continue with remaining chapters rather than failing entirely
            continue

    print("\nDone. All chapters processed.")


if __name__ == "__main__":
    asyncio.run(main())
