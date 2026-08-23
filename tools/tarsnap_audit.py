#!/usr/bin/env python3
"""Conservative source scanner for the Tarsnap bug-bounty audit.

This does not assert that a match is a bug. It produces a compact, reviewable
candidate inventory for manual validation and de-duplication.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


EXCLUDED_PARTS = {
    ".git",
    "autom4te.cache",
    "libarchive",  # vendored; only substantive bugs are bounty-eligible
    "external",
}


@dataclass(frozen=True)
class Rule:
    name: str
    rationale: str
    pattern: re.Pattern[str]


RULES = [
    Rule(
        "subtraction-in-loop-bound",
        "Unsigned `len - 1 - i` style bounds can underflow for zero-length inputs.",
        re.compile(r"for\s*\([^;]*;[^;]*(?:<|<=)[^;]*\b[A-Za-z_]\w*\s*-\s*1\s*-\s*[A-Za-z_]\w*[^;]*;", re.S),
    ),
    Rule(
        "addition-in-bound-check",
        "`a + b <= limit` can wrap before the comparison; subtraction form is often safer.",
        re.compile(r"\bif\s*\([^\n;]{0,180}\b[A-Za-z_]\w*\s*\+\s*\*?[A-Za-z_]\w*\s*(?:<=|<|>=|>)", re.S),
    ),
    Rule(
        "variable-sized-fread-count-one",
        "`fread(ptr, len, 1, ...)` returns zero when len is zero and is often mishandled as an error.",
        re.compile(r"fread\s*\([^,]+,\s*[A-Za-z_]\w*\s*,\s*1\s*,", re.S),
    ),
    Rule(
        "direct-realloc-assignment",
        "Assigning realloc directly to the owned pointer can lose the original allocation on failure.",
        re.compile(r"\b([A-Za-z_]\w*)\s*=\s*realloc\s*\(\s*\1\s*,", re.S),
    ),
    Rule(
        "unchecked-strdup-assignment",
        "An unchecked strdup result can become a later NULL dereference under memory pressure.",
        re.compile(r"\b[A-Za-z_]\w*(?:->|\.)?[A-Za-z_]*\s*=\s*strdup\s*\([^;]+\);", re.S),
    ),
    Rule(
        "decoded-value-directly-to-flags",
        "Persisted integers assigned directly to in-memory flag words may import ownership/control bits.",
        re.compile(r"\b(?:flags|[A-Za-z_]\w*_flags)\s*=\s*(?:le|be)(?:16|32|64)dec\s*\(", re.S),
    ),
    Rule(
        "memcpy-from-packet-offset",
        "Packet offsets deserve cross-checking against length checks, HMAC coverage, and protocol docs.",
        re.compile(r"memcpy\s*\([^;]+(?:packetbuf|packet|buf)\s*\+?\s*\[?\s*\d+", re.S),
    ),
    Rule(
        "signed-cast-from-decoded-unsigned",
        "Large encoded values cast to signed time/off/int types can wrap into negative values.",
        re.compile(r"\([^)]*(?:time_t|off_t|int)\s*\)\s*(?:le|be)(?:32|64)dec\s*\(", re.S),
    ),
]


def source_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".c", ".h"}:
            continue
        rel = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in rel.parts):
            continue
        yield path


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def snippet(text: str, start: int, end: int) -> str:
    left = text.rfind("\n", 0, start)
    right = text.find("\n", end)
    left = 0 if left < 0 else left + 1
    right = len(text) if right < 0 else right
    value = text[left:right].strip().replace("\t", "    ")
    return value[:500]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, default=Path("audit-candidates.md"))
    args = parser.parse_args()

    root = args.root.resolve()
    findings: dict[str, list[tuple[str, int, str]]] = {rule.name: [] for rule in RULES}

    for path in source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        for rule in RULES:
            for match in rule.pattern.finditer(text):
                findings[rule.name].append(
                    (rel, line_number(text, match.start()), snippet(text, match.start(), match.end()))
                )

    lines = [
        "# Tarsnap audit candidate inventory",
        "",
        "Generated mechanically. Every entry requires source review, reproduction, and duplicate checking before reporting.",
        "",
    ]
    for rule in RULES:
        items = findings[rule.name]
        lines.extend(
            [
                f"## {rule.name} ({len(items)})",
                "",
                rule.rationale,
                "",
            ]
        )
        for rel, lineno, value in items[:200]:
            lines.append(f"- `{rel}:{lineno}` — `{value.replace('`', "'")}`")
        if len(items) > 200:
            lines.append(f"- … {len(items) - 200} more omitted")
        lines.append("")

    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
