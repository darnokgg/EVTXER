#!/usr/bin/env python3
"""Exact, byte-safe text replacement for EVTXER's mixed-encoding files.

The launcher and code\\wpf-*.ps1 are CRLF + UTF-8 BOM; the lib, tests, README.txt
and docs are LF without BOM. Git Bash's sed strips CRs, heredocs and
`python -c` eat backslashes. So: write a spec file with the Write tool (nothing
in it is escaped) and run

  python -I tools/dev/patch.py <spec.txt> [--dry-run]

Spec format - any number of blocks, paths relative to the repo:

  === FILE code/wpf-collect.ps1
  <<<< OLD
  exact old text (LF in the spec; matched against the file's own line endings)
  ==== NEW
  replacement text
  >>>> END

Every OLD must match exactly once, or nothing is written at all. A file keeps
its line endings and its BOM (or lack of one). Prints what changed.
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BLOCK = re.compile(r"^<<<< OLD\n(.*?)\n==== NEW\n(.*?)\n?>>>> END$", re.S | re.M)


def parse(spec):
    """[(file, [(old, new), ...]), ...] - split() alternates file name and body."""
    parts = re.split(r"^=== FILE (.+)$", spec, flags=re.M)[1:]
    return [(f.strip(), [m.groups() for m in BLOCK.finditer(body)]) for f, body in zip(parts[0::2], parts[1::2])]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    spec = open(sys.argv[1], encoding="utf-8-sig").read().replace("\r\n", "\n")
    dry = "--dry-run" in sys.argv
    plans = {}
    for rel, reps in parse(spec):          # two blocks for one file apply in order
        plans.setdefault(rel, []).extend(reps)
    plans = list(plans.items())
    if not plans or any(not reps for _, reps in plans):
        sys.exit("no '=== FILE' block with at least one OLD/NEW pair")
    staged = []
    for rel, reps in plans:
        path = os.path.join(REPO, rel)
        data = open(path, "rb").read()
        bom = data.startswith(b"\xef\xbb\xbf")
        text = data[3 if bom else 0:].decode("utf-8")
        crlf = "\r\n" in text
        if crlf and re.search(r"(?<!\r)\n", text):
            sys.exit(f"{rel}: mixed line endings - fix that first")
        for i, (old, new) in enumerate(reps, 1):
            o, n = (old.replace("\n", "\r\n"), new.replace("\n", "\r\n")) if crlf else (old, new)
            c = text.count(o)
            if c != 1:
                sys.exit(f"{rel}: replacement {i} matches {c} times (needs exactly 1) - nothing written:\n{old[:200]}")
            text = text.replace(o, n)
        staged.append((rel, path, (b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8"), crlf, bom, len(reps)))
    for rel, path, out, crlf, bom, n in staged:
        if not dry:
            open(path, "wb").write(out)
        print(f"{'would patch' if dry else 'patched'} {rel}: {n} replacement(s), "
              f"{'CRLF' if crlf else 'LF'}{' + BOM' if bom else ''} kept")


if __name__ == "__main__":
    main()
