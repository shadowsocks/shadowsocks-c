#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject heap allocation in the C++ sources under src/.

The C++ core follows a "no heap after startup" policy (docs/modernization.md):
connections, buffers, crypto contexts and sessions come from fixed pools that
are reserved once at startup. This lint keeps allocating constructs out of
C++ code so the policy cannot erode one convenience at a time.

Only C++ files (.cpp, .hpp) are checked; the legacy C sources are ported
module by module and keep their ss_malloc calls until then.

A line that must allocate (a startup reservation) carries a justification:

    void *base = std::calloc(1, size); // heap-ok: startup reservation

Modules converted mechanically from C still allocate the way the C code did
until they are rewritten. scripts/no_heap_baseline.txt lists them with their
current violation counts, and works as a ratchet: a file may not gain
violations, and when it loses some the baseline must be lowered to match.

Usage: check_no_heap.py [--root DIR] [--baseline FILE] [--self-test]
"""

import argparse
import pathlib
import re
import sys

ALLOW_MARKER = "heap-ok:"

# (pattern, explanation). Patterns run on code with comments and string
# literals blanked out.
FORBIDDEN = [
    (re.compile(r"\b(?:std::)?(?:malloc|calloc|realloc|aligned_alloc|posix_memalign|strdup|strndup)\s*\("),
     "C allocator call"),
    (re.compile(r"\bss_(?:malloc|realloc|aligned_malloc|strndup)\s*\("), "ss_* allocator call"),
    (re.compile(r"\b(?:std::)?free\s*\("), "free(); memory comes from pools, not malloc"),
    # `new T`, `new T[n]`, `::new T` -- but not placement new `new (p) T`.
    (re.compile(r"(?<![\w.>])(?:::)?new\s+(?!\()[A-Za-z_:]"), "operator new"),
    (re.compile(r"\bdelete(?:\s*\[\s*\])?\s+[A-Za-z_*(]"), "operator delete"),
    (re.compile(r"\bstd::(?:make_unique|make_shared|allocate_shared|make_unique_for_overwrite)\b"),
     "heap-allocating smart pointer factory; acquire from an ObjectPool"),
    (re.compile(r"\bstd::(?:shared_ptr|weak_ptr)\b"), "std::shared_ptr; use ss::RefPtr over a pool"),
    (re.compile(r"\bstd::(?:vector|deque|list|forward_list|map|multimap|set|multiset|"
                r"unordered_map|unordered_multimap|unordered_set|unordered_multiset)\s*<"),
     "allocating container; use std::array, std::span or src/core containers"),
    (re.compile(r"\bstd::(?:string|wstring|u8string|stringstream|ostringstream|istringstream|function)\b"),
     "allocating type; use std::string_view, a FixedBuffer or a function pointer"),
]


def strip_comments_and_strings(text):
    """Blank out comments and string/char literals, preserving line breaks."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(c + " " * (j - i - 2) + c if j - i >= 2 else c)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check_text(text):
    """Return a list of (line_number, explanation, source_line) violations."""
    problems = []
    raw_lines = text.splitlines()
    code_lines = strip_comments_and_strings(text).splitlines()
    for number, (raw, code) in enumerate(zip(raw_lines, code_lines), start=1):
        if ALLOW_MARKER in raw:
            continue
        for pattern, why in FORBIDDEN:
            if pattern.search(code):
                problems.append((number, why, raw.strip()))
                break
    return problems


def read_baseline(path):
    baseline = {}
    if path is None or not path.exists():
        return baseline
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            name, count = line.split()
            baseline[name] = int(count)
    return baseline


def check_tree(root, baseline):
    src = root / "src"
    files = sorted(p for p in src.rglob("*") if p.suffix in (".cpp", ".hpp") and "blake3" not in p.parts)
    ok = True
    total = 0
    for path in files:
        name = path.relative_to(root).as_posix()
        problems = check_text(path.read_text(encoding="utf-8"))
        allowed = baseline.pop(name, 0)
        total += len(problems)
        if len(problems) > allowed:
            for number, why, line in problems:
                print(f"{name}:{number}: {why}: {line}")
            print(f"{name}: {len(problems)} violation(s), baseline allows {allowed}")
            ok = False
        elif len(problems) < allowed:
            print(f"{name}: {len(problems)} violation(s), below the baseline of {allowed}; "
                  "lower it in scripts/no_heap_baseline.txt")
            ok = False
    for name in sorted(baseline):
        print(f"{name}: listed in the baseline but not a C++ source; remove the entry")
        ok = False
    print(f"check_no_heap: {len(files)} C++ files, {total} baselined or new violation(s)")
    return ok


def self_test():
    bad = {
        "int *p = (int *)malloc(4);": True,
        "auto *c = new Conn();": True,
        "auto *c = ::new Conn;": True,
        "delete c;": True,
        "std::vector<int> v;": True,
        "std::string name;": True,
        "std::function<void()> cb;": True,
        "auto p = std::make_unique<int>(1);": True,
        "std::shared_ptr<T> s;": True,
        "ss_free(ptr);": False,  # not a call pattern we flag (macro wraps free)
        "free(buf);": True,
    }
    good = [
        "std::construct_at(p, 1);",
        "::new (static_cast<void *>(p)) T(1);",
        "Foo(const Foo &) = delete;",
        "std::string_view name;",
        "std::array<std::byte, 16> key;",
        "// std::vector<int> mentioned in a comment",
        'log("new connection from %s", addr);',
        "void *b = std::calloc(1, n); // heap-ok: startup reservation",
        "bool renew_lease = true;",
        "conn.free_slots();",
    ]
    ok = True
    for line, expect in bad.items():
        got = bool(check_text(line))
        if got != expect:
            print(f"self-test: expected {'violation' if expect else 'clean'} for: {line}")
            ok = False
    for line in good:
        if check_text(line):
            print(f"self-test: false positive for: {line}")
            ok = False
    print("check_no_heap self-test:", "ok" if ok else "FAILED")
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent)
    parser.add_argument("--baseline", type=pathlib.Path,
                        help="ratchet file (default: scripts/no_heap_baseline.txt under --root)")
    parser.add_argument("--self-test", action="store_true", help="run the pattern self-test first")
    args = parser.parse_args()
    if args.self_test and not self_test():
        return 1
    root = args.root.resolve()
    baseline = read_baseline(args.baseline or root / "scripts" / "no_heap_baseline.txt")
    return 0 if check_tree(root, baseline) else 1


if __name__ == "__main__":
    sys.exit(main())
