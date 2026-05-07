#!/usr/bin/env python3
"""
Bistouri Documentation Generator

Reads the Bistouri source code and generates per-module Quarto (.qmd) chapters
using Gemini 3.1 Pro. Designed for the free tier: chunked context per chapter
and rate-limited to 5 requests/minute.

Usage:
    GEMINI_API_KEY=<key> python scripts/generate_docs.py
"""

import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import google.genai as genai

# ── Configuration ────────────────────────────────────────────────────────────

# Model to use for generation.
# "gemini-2.5-flash" is the stable free-tier model.
# Upgrade to "gemini-3-flash-preview" once your project has free-tier access to it.
MODEL = "gemini-3-flash-preview"
DOCS_DIR = Path("docs")
RATE_LIMIT_SECONDS = 12  # 5 requests/minute = 1 every 12 seconds

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
- Use mermaid diagrams for data flow and state machines — they should clarify
  relationships that prose alone cannot.
- A reader should finish each chapter able to explain the design to someone
  else without looking at the code.
- If a chapter is not interesting — if it does not teach something surprising
  or non-obvious — output only the YAML frontmatter with a comment:
  <!-- Nothing interesting to document here yet. -->

STABILITY AND CONSERVATISM:
- Be conservative about changes. Documentation should evolve incrementally,
  not be rewritten from scratch each time.
- If you receive an existing chapter: preserve its tone, structure, and prose
  style. Only update what is factually stale or missing.
- If the code has not changed meaningfully since the last version, return the
  existing chapter UNCHANGED. Do not rephrase for the sake of rephrasing.
- Never reorganize sections. The skeleton is fixed.

OUTPUT FORMAT:
1. Valid Quarto Markdown (.qmd).
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

CURRENT CHAPTER:
{existing_chapter_content}

SECTION SKELETON (must match exactly):
{skeleton}

CURRENT SOURCE CODE:
{code_context}
"""

# ── Chapter definitions ──────────────────────────────────────────────────────

CHAPTERS = [
    {
        "filename": "overview.qmd",
        "title": "Architecture & Design Philosophy",
        "sources": ["src/main.rs", "src/args.rs", "AGENTS.md", "Cargo.toml"],
        "skeleton": (
            """\
## What is Bistouri?
## Why eBPF for Profiling?
## Architecture at a Glance
## Component Map (use a ```mermaid``` flowchart)
## The Event Pipeline
## Design Principles
## Key Tradeoffs"""
        ),
    },
    {
        "filename": "trigger.qmd",
        "title": "Trigger Agent",
        "sources": ["src/trigger/"],
        "skeleton": (
            """\
## The Problem: When to Profile?
## PSI as a Trigger Mechanism
## Trie-Based Process Routing
## Configuration Matching & Glob Semantics
## The proc_walk Loop
## Hot Reload Without Downtime
## Eventual Consistency Model
## Data Flow (use a ```mermaid``` diagram)"""
        ),
    },
    {
        "filename": "profiler.qmd",
        "title": "Profiler Agent",
        "sources": ["src/agent/"],
        "skeleton": (
            """\
## From Trigger to Stack Trace
## BPF Map Lifecycle
## Ring Buffer vs Perf Buffer
## LPM Trie for Cgroup Matching
## Batch Updates & Performance
## Error Recovery
## Agent Lifecycle (use a ```mermaid``` diagram)"""
        ),
    },
    {
        "filename": "ebpf.qmd",
        "title": "eBPF Programs",
        "sources": ["src/bpf/", "build.rs"],
        "skeleton": (
            """\
## eBPF in 5 Minutes
## The Profiler Program
## Shared Data Structures (Kernel ↔ Userspace)
## Satisfying the Verifier
## Build Pipeline (libbpf-cargo)
## Memory Layout & repr(C)
## Program Flow (use a ```mermaid``` diagram)"""
        ),
    },
]

# ── Source file extensions to include ────────────────────────────────────────

SOURCE_EXTENSIONS = {".rs", ".c", ".h", ".toml", ".md", ".yml", ".yaml"}


# ── Helpers ──────────────────────────────────────────────────────────────────


def get_commit_sha() -> str:
    """Get the short SHA of the current HEAD commit."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def read_sources(paths: list[str]) -> str:
    """Concatenate relevant source files into a single context string."""
    context = ""
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file() and f.suffix in SOURCE_EXTENSIONS:
                    context += f"\n--- File: {f} ---\n{f.read_text()}\n"
        elif path.is_file():
            context += f"\n--- File: {path} ---\n{path.read_text()}\n"
    return context


def generate_chapter(
    client: genai.Client,
    chapter: dict,
    commit_sha: str,
    date_str: str,
) -> None:
    """Generate or incrementally update a single .qmd chapter via Gemini."""
    code_context = read_sources(chapter["sources"])
    output_path = DOCS_DIR / chapter["filename"]

    # Decide: incremental update or first draft
    existing_content = None
    if output_path.exists():
        content = output_path.read_text().strip()
        # Only treat as existing if it has real content (not just a placeholder)
        if content and "# Placeholder" not in content:
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
    )

    response = client.models.generate_content(
        model=MODEL,
        contents=user_prompt,
        config=genai.types.GenerateContentConfig(
            system_instruction=system_instruction,
        ),
    )

    output_path.write_text(response.text)
    print(f"  ✓ {chapter['filename']}")


def main() -> None:
    """Generate all documentation chapters."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(
            "ERROR: GEMINI_API_KEY environment variable is not set.",
            file=sys.stderr,
        )
        sys.exit(1)

    client = genai.Client(api_key=api_key)
    commit_sha = get_commit_sha()
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    DOCS_DIR.mkdir(exist_ok=True)

    print(f"Generating docs from commit {commit_sha} ({date_str})")
    print(f"Model: {MODEL}")
    print(f"Rate limit: {RATE_LIMIT_SECONDS}s between calls\n")

    for i, chapter in enumerate(CHAPTERS):
        # Rate limit: wait between calls (skip before the first one)
        if i > 0:
            print(f"  ⏳ Rate limiting ({RATE_LIMIT_SECONDS}s)...")
            time.sleep(RATE_LIMIT_SECONDS)

        print(f"  Generating {chapter['filename']}...")
        try:
            generate_chapter(client, chapter, commit_sha, date_str)
        except Exception as e:
            print(f"  ✗ {chapter['filename']}: {e}", file=sys.stderr)
            # Continue with remaining chapters rather than failing entirely
            continue

    print("\nDone. All chapters processed.")


if __name__ == "__main__":
    main()
