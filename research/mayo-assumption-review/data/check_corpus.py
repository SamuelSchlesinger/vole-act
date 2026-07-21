#!/usr/bin/env python3
"""Validate corpus reachability, local Markdown links, and source anchors."""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "index.md"
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
REF = re.compile(r"^\[([^\]]+)\]:\s+(.+)$", re.MULTILINE)
CITATION = re.compile(r"\[([a-z][a-z0-9-]*)\]\[\1\]")
ANCHOR = re.compile(r'<a\s+id="([^"]+)"')


def local_target(source: Path, raw: str) -> tuple[Path, str | None] | None:
    target = raw.strip().split()[0].strip("<>")
    if target.startswith(("http://", "https://", "mailto:")):
        return None
    path_part, sep, anchor = target.partition("#")
    path = source if not path_part else (source.parent / path_part).resolve()
    return path, anchor if sep else None


def main() -> None:
    markdown = sorted(ROOT.rglob("*.md"))
    errors: list[str] = []
    edges: dict[Path, set[Path]] = {path.resolve(): set() for path in markdown}

    for path in markdown:
        text = path.read_text(encoding="utf-8")
        definitions = dict(REF.findall(text))
        for citation in sorted(set(CITATION.findall(text))):
            if citation not in definitions:
                errors.append(
                    f"{path.relative_to(ROOT)}: undefined citation [{citation}]"
                )
        for key, raw in definitions.items():
            resolved = local_target(path.resolve(), raw)
            if resolved is None:
                continue
            target, anchor = resolved
            if target == (ROOT / "sources.md").resolve() and anchor != key:
                errors.append(
                    f"{path.relative_to(ROOT)}: citation [{key}] must target "
                    f"the canonical sources.md#{key} anchor, not #{anchor}"
                )
        raw_targets = LINK.findall(text) + list(definitions.values())
        for raw in raw_targets:
            resolved = local_target(path.resolve(), raw)
            if resolved is None:
                continue
            target, anchor = resolved
            if not target.exists():
                errors.append(f"{path.relative_to(ROOT)}: missing {raw}")
                continue
            inside = target == ROOT or ROOT in target.parents
            if target.suffix == ".md" and inside:
                edges[path.resolve()].add(target)
            if anchor and target.suffix == ".md" and inside:
                target_text = target.read_text(encoding="utf-8")
                anchors = set(ANCHOR.findall(target_text))
                headings = {
                    re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
                    for heading in re.findall(r"^#{1,6}\s+(.+)$", target_text, re.MULTILINE)
                }
                if anchor not in anchors | headings:
                    errors.append(
                        f"{path.relative_to(ROOT)}: missing anchor #{anchor} in "
                        f"{target.relative_to(ROOT)}"
                    )

    seen: set[Path] = set()
    todo = deque([ENTRY.resolve()])
    while todo:
        path = todo.popleft()
        if path in seen:
            continue
        seen.add(path)
        todo.extend(edges.get(path, ()))

    unreachable = sorted(set(edges) - seen)
    for path in unreachable:
        errors.append(f"unreachable from index.md: {path.relative_to(ROOT)}")

    if errors:
        raise SystemExit("\n".join(errors))
    print(
        f"ok: {len(markdown)} markdown files reachable; "
        "local links and citation definitions valid"
    )


if __name__ == "__main__":
    main()
