#!/usr/bin/env python3
"""Sanity-check UI localizations.

* every .strings file parses and has no duplicate keys;
* every translation keeps the key's format specifiers (%lld, %@, %d, ...) in order;
* every localization has exactly the same key set as en.lproj;
* every key is actually used somewhere in Sources/ (interpolations become specifiers).

Exit code 1 on any problem — used by CI.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOC = ROOT / "Localization"
SPEC = re.compile(r"%(?:\d+\$)?[-+ #0]*\d*(?:\.\d+)?(?:lld|ld|d|@|f|lf|s)")
ENTRY = re.compile(r'^"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)";\s*$')


def unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")


def load(path: pathlib.Path) -> dict:
    out, errors = {}, []
    text = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.strip().startswith("//"):
            continue
        m = ENTRY.match(line.strip())
        if not m:
            errors.append(f"{path}:{n}: cannot parse: {line.strip()}")
            continue
        k, v = unescape(m.group(1)), unescape(m.group(2))
        if k in out:
            errors.append(f"{path}:{n}: duplicate key {k!r}")
        out[k] = v
    if errors:
        raise SystemExit("\n".join(errors))
    return out


def key_regex(key: str) -> re.Pattern:
    # Each specifier corresponds to a \( ... ) interpolation in the Swift literal.
    parts = SPEC.split(key)
    body = r"\\\(.+?\)".join(re.escape(p) for p in parts)
    return re.compile('"' + body + '"')


def main() -> int:
    problems = []
    base = load(LOC / "en.lproj" / "Localizable.strings")
    sources = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "Sources").rglob("*.swift"))

    for key in base:
        if not key_regex(key).search(sources):
            problems.append(f"unused key (not found in Sources/): {key!r}")

    for lproj in sorted(LOC.glob("*.lproj")):
        table = load(lproj / "Localizable.strings")
        missing, extra = base.keys() - table.keys(), table.keys() - base.keys()
        problems += [f"{lproj.name}: missing {k!r}" for k in sorted(missing)]
        problems += [f"{lproj.name}: unknown {k!r}" for k in sorted(extra)]
        for k, v in table.items():
            if SPEC.findall(k) != SPEC.findall(v):
                problems.append(f"{lproj.name}: specifier mismatch {k!r} -> {v!r}")
        load(lproj / "InfoPlist.strings")

    for p in problems:
        print(p, file=sys.stderr)
    print(f"checked {len(base)} keys in {len(list(LOC.glob('*.lproj')))} localizations: "
          f"{'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
