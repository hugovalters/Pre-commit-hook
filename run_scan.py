#!/usr/bin/env python3
# Copyright 2026 Valters Capital, SIA
# Licensed under the Apache License, Version 2.0.
# ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
# Maintained by Hugo Valters

"""
ValtersIT pre-commit hook

Called by pre-commit with the dependency lockfiles / manifests staged in the
current commit (see .pre-commit-hooks.yaml for the exact file pattern). It
reads the pinned package versions from those files, submits them to the
ValtersIT API as one scan, and prints any CVEs matched.

Understood files:
  requirements*.txt              Python, `name==version` lines
  package-lock.json,
  npm-shrinkwrap.json            npm, lockfile v1/v2/v3
  Gemfile.lock                   RubyGems
  composer.lock                  Composer / Packagist
  packages.lock.json             NuGet lock file
  *.csproj, *.fsproj, *.vbproj   NuGet <PackageReference> with an exact Version
  packages.config                NuGet (legacy)

Only package names and versions are read from those files; nothing else in
the repository is opened, and nothing is written.

By default the hook never blocks a commit - it reports. With
--fail-on-cvss SCORE it fails when the API response lists a matched CVE
whose `cvss` is at or above SCORE.

pre-commit runs hooks without an interactive terminal, so the authorised-use
confirmation is given once, beforehand, with:
    python3 run_scan.py --confirm
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import valtersit_client as vit  # noqa: E402

TOOL_NAME = "pre-commit-hook"


# ---------------------------------------------------------------------------
# Parsers - each returns a list of {"vendor", "product", "version"}
# ---------------------------------------------------------------------------

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)")


def parse_requirements(text: str, include_dev: bool) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        m = _REQ_LINE.match(line) if line and not line.startswith(("#", "-")) else None
        if m:
            name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
            out.append({"vendor": "PyPI", "product": name, "version": m.group(2)})
    return out


def parse_package_lock(text: str, include_dev: bool) -> list[dict]:
    lock = json.loads(text)
    out = []
    if isinstance(lock.get("packages"), dict):
        for path, meta in lock["packages"].items():
            if not path or not isinstance(meta, dict) or meta.get("link") or "node_modules/" not in path:
                continue
            if meta.get("dev") and not include_dev:
                continue
            if meta.get("version"):
                name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
                out.append({"vendor": "npm", "product": name, "version": meta["version"]})
        return out

    def walk(deps):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version") or ""
            if version and not (meta.get("dev") and not include_dev) \
                    and not version.startswith(("file:", "link:", "git", "http")):
                out.append({"vendor": "npm", "product": name, "version": version})
            walk(meta.get("dependencies"))

    walk(lock.get("dependencies"))
    return out


def parse_gemfile_lock(text: str, include_dev: bool) -> list[dict]:
    out, section, in_specs = [], None, False
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section, in_specs = line.strip(), False
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and section in ("GEM", "GIT", "PATH"):
            m = re.match(r"^    ([A-Za-z0-9][A-Za-z0-9._-]*) \(([^)]+)\)\s*$", line)
            if m:
                out.append({"vendor": "RubyGems", "product": m.group(1), "version": m.group(2).split("-", 1)[0]})
    return out


def parse_composer_lock(text: str, include_dev: bool) -> list[dict]:
    data = json.loads(text)
    pkgs = list(data.get("packages", []) or [])
    if include_dev:
        pkgs += list(data.get("packages-dev", []) or [])
    out = []
    for p in pkgs:
        if p.get("name") and p.get("version"):
            v = p["version"]
            out.append({"vendor": "Packagist", "product": p["name"], "version": v[1:] if re.match(r"^v\d", v) else v})
    return out


def parse_nuget_lock(text: str, include_dev: bool) -> list[dict]:
    data = json.loads(text.lstrip("﻿"))
    out = []
    for deps in (data.get("dependencies") or {}).values():
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("type") != "Project" and meta.get("resolved"):
                out.append({"vendor": "NuGet", "product": name, "version": meta["resolved"]})
    return out


def _xml_root(text: str):
    root = ET.fromstring(text.lstrip("﻿"))
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def parse_project_file(text: str, include_dev: bool) -> list[dict]:
    out = []
    for ref in _xml_root(text).iter("PackageReference"):
        name = ref.get("Include") or ref.get("Update")
        version = ref.get("Version")
        if version is None and ref.find("Version") is not None:
            version = (ref.find("Version").text or "").strip()
        m = re.match(r"^\[?\s*([0-9][0-9A-Za-z.+-]*)\s*\]?$", version or "")
        if name and m and "," not in version and "*" not in version:
            out.append({"vendor": "NuGet", "product": name, "version": m.group(1)})
    return out


def parse_packages_config(text: str, include_dev: bool) -> list[dict]:
    return [{"vendor": "NuGet", "product": p.get("id"), "version": p.get("version")}
            for p in _xml_root(text).iter("package") if p.get("id") and p.get("version")]


def parser_for(path: Path):
    name = path.name
    if re.match(r"^requirements[^/]*\.txt$", name):
        return parse_requirements
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return parse_package_lock
    if name == "Gemfile.lock":
        return parse_gemfile_lock
    if name == "composer.lock":
        return parse_composer_lock
    if name == "packages.lock.json":
        return parse_nuget_lock
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return parse_project_file
    if name == "packages.config":
        return parse_packages_config
    return None


# ---------------------------------------------------------------------------
# Result handling
# ---------------------------------------------------------------------------

def matched_scores(body) -> list[tuple]:
    """(cve_id, slug, version, cvss) for every result in the API response
    that carries a numeric cvss. Unknown response shapes yield []."""
    rows = []
    results = body.get("results") if isinstance(body, dict) else None
    for r in results or []:
        if isinstance(r, dict) and isinstance(r.get("cvss"), (int, float)):
            rows.append((r.get("cve_id", "?"), r.get("slug", "?"), r.get("version", "?"), float(r["cvss"])))
    return rows


def main():
    parser = argparse.ArgumentParser(description="ValtersIT pre-commit hook: scan staged dependency lockfiles.")
    parser.add_argument("files", nargs="*", help="Files passed by pre-commit.")
    parser.add_argument("--confirm", action="store_true",
                        help="Show the authorised-use notice and record your confirmation (run once, interactively).")
    parser.add_argument("--include-dev", action="store_true",
                        help="Also include development dependencies (devDependencies, packages-dev).")
    parser.add_argument("--fail-on-cvss", type=float, metavar="SCORE",
                        help="Fail the hook if a matched CVE has a CVSS score at or above SCORE (e.g. 7.0).")
    args = parser.parse_args()

    if args.confirm:
        sys.exit(0 if vit.require_consent(TOOL_NAME, non_interactive=False) else 1)

    if not args.files:
        return
    if not vit.require_consent(TOOL_NAME, non_interactive=True):
        print("[!] Confirm authorised use once by running, in a terminal:\n"
              "      python3 {} --confirm".format(Path(__file__).resolve()), file=sys.stderr)
        sys.exit(1)

    inventory, seen = [], set()
    for f in args.files:
        path = Path(f)
        fn = parser_for(path)
        if fn is None or not path.is_file():
            continue
        try:
            comps = fn(path.read_text(encoding="utf-8", errors="replace"), args.include_dev)
        except (ValueError, ET.ParseError) as exc:
            print("[!] Could not parse {}: {}".format(f, exc), file=sys.stderr)
            continue
        print("[i] {}: {} pinned package(s)".format(f, len(comps)))
        for c in comps:
            key = (c["vendor"], c["product"], c["version"])
            if key not in seen:
                seen.add(key)
                inventory.append(dict(c, slug=c["product"]))

    if not inventory:
        print("[i] No pinned packages found in the staged files - nothing to scan.")
        return

    result = vit.submit_scan(inventory)
    if result.get("reason") == "no_api_key":
        print("[i] VALTERSIT_API_KEY is not set - skipping the CVE scan (commit not blocked).")
        return
    if not result["available"]:
        print("[!] " + vit.explain_status(result["status"], result["body"]) + " (commit not blocked)",
              file=sys.stderr)
        return

    matches = matched_scores(result["body"])
    print("[+] Scan submitted. {} component(s) sent for matching.".format(len(inventory)))
    if matches:
        print()
        print("  {:<18} {:<34} {:<14} {}".format("CVE", "Package", "Version", "CVSS"))
        for cve, slug, version, score in sorted(matches, key=lambda m: -m[3]):
            print("  {:<18} {:<34} {:<14} {:.1f}".format(cve, slug[:34], version[:14], score))
        print("\n  Details: https://www.valtersit.com/cve/<CVE-ID>/")
    else:
        print(json.dumps(result["body"], indent=2))

    if args.fail_on_cvss is not None:
        worst = max((m[3] for m in matches), default=None)
        if worst is not None and worst >= args.fail_on_cvss:
            print("\n[!] Matched CVE with CVSS {:.1f} >= {:.1f} - blocking the commit (--fail-on-cvss). "
                  "Update the dependency, or commit with --no-verify if you must.".format(worst, args.fail_on_cvss),
                  file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
