"""Run the pipeline on real CVE fix commits (vulnerable -> patched).

For each CVE the harness fetches the commit `.diff` (no API, so no rate limit),
reconstructs the *before* revision of every changed source file by reverse-
applying the diff to the commit's raw content, and runs the same
vulnerable-vs-patched comparison as the web UI.

Usage:
    python benchmarks/run_cves.py [--cases benchmarks/cve_cases.json] [--limit 3]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from manifold.server import _compare

UA = {"User-Agent": "manifold-cve-harness"}
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _get(url: str) -> bytes:
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40).read()


def _raw(repo: str, sha: str, path: str):
    try:
        return _get(f"https://raw.githubusercontent.com/{repo}/{sha}/{path}").decode("utf-8", "replace")
    except Exception:
        return None


def _diff(repo: str, sha: str) -> str:
    return _get(f"https://github.com/{repo}/commit/{sha}.diff").decode("utf-8", "replace")


def _parse(diff_text: str):
    """Parse a unified diff into [(path, [(after_start, [(kind, text), ...])]), ...]."""
    files, cur = [], None
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            cur = {"path": None, "hunks": []}
            files.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("+++ b/"):
            cur["path"] = line[6:].strip()
            continue
        if line.startswith("@@"):
            m = _HUNK.match(line)
            if m:
                cur["hunks"].append((int(m.group(1)), []))
            continue
        if line.startswith("--- ") or line.startswith("index ") or line.startswith("\\"):
            continue
        if cur["hunks"] and line[:1] in (" ", "+", "-"):
            cur["hunks"][-1][1].append((line[0], line[1:]))
    return files


def _reverse_apply(after: str, hunks) -> str | None:
    lines = after.splitlines(keepends=True)
    for start, body in reversed(hunks):  # last to first keeps indices stable
        after_block = [t for k, t in body if k in (" ", "+")]
        before_block = [t for k, t in body if k in (" ", "-")]
        i = start - 1
        actual = lines[i : i + len(after_block)]
        if actual == after_block:
            lines[i : i + len(after_block)] = before_block
        else:  # try to locate the block elsewhere
            joined = "".join(actual)
            pos = None
            for j in range(max(0, i - 200), min(len(lines), i + 200)):
                if lines[j : j + len(after_block)] == after_block:
                    pos = j
                    break
            if pos is None:
                return None
            lines[pos : pos + len(after_block)] = before_block
    return "".join(lines)


def _is_source(path: str) -> bool:
    low = path.lower()
    return (path.endswith(".py") or path.endswith(".java")) and "/test" not in low \
        and "test_" not in low and "/docs/" not in low


def run_case(case: dict, keep_code: bool = False) -> dict:
    repo, sha = case["repo"], case["commit"]
    try:
        files = _parse(_diff(repo, sha))
    except Exception as exc:
        return {"cve": case["cve"], "repo": repo, "error": str(exc)}
    records = []
    for spec in files:
        path = spec["path"]
        if not path or not _is_source(path):
            continue
        after = _raw(repo, sha, path)
        if not after:
            continue
        before = _reverse_apply(after, spec["hunks"])
        if before is None:
            continue
        adapter = "java" if path.endswith(".java") else "python"
        cmp = _compare({"vulnerable": before, "patched": after, "adapter": adapter, "path": path})
        rec = {
            "file": path, "adapter": adapter,
            "vuln_findings": len(cmp["vulnerable"]["findings"]),
            "patched_findings": len(cmp["patched"]["findings"]),
            "resolved": cmp["diff"]["resolved"],
            "persisting": cmp["diff"]["persisting"],
        }
        if keep_code:
            rec["vulnerable"] = before
            rec["patched"] = after
        records.append(rec)
        if len(records) >= case.get("max_files", 8):
            break
    return {"cve": case["cve"], "repo": repo, "url": case.get("url", ""), "files": records}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(ROOT / "benchmarks" / "cve_cases.json"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--dump-pairs", action="store_true",
                    help="also write benchmarks/cve_pairs.json with the before/after code")
    args = ap.parse_args()

    cases = json.loads(Path(args.cases).read_text())
    if args.limit:
        cases = cases[: args.limit]

    results, resolved_total, analyzed = [], 0, 0
    for case in cases:
        r = run_case(case, keep_code=args.dump_pairs)
        results.append(r)
        print(f"== {r['cve']}  {r.get('repo','')}")
        if r.get("error"):
            print(f"   error: {r['error']}")
            continue
        for f in r["files"]:
            analyzed += 1
            resolved_total += 1 if f["resolved"] else 0
            mark = "RESOLVED" if f["resolved"] and not f["persisting"] else ("partial" if f["resolved"] else "-")
            print(f"   {f['file']:<52} vuln={f['vuln_findings']} patched={f['patched_findings']} "
                  f"resolved={len(f['resolved'])} persisting={len(f['persisting'])} [{mark}]")
        if not r["files"]:
            print("   (no analyzable source files changed)")

    print(f"\nsummary: {resolved_total}/{analyzed} analyzed files resolved a finding")

    if args.dump_pairs:
        pairs = []
        for r in results:
            for f in r.get("files", []):
                if not (f["resolved"] or f["vuln_findings"]):
                    continue  # only keep loadable pair(s) of interest
                pairs.append({
                    "cve": r["cve"], "repo": r.get("repo", ""), "file": f["file"],
                    "adapter": f["adapter"], "resolved": bool(f["resolved"]),
                    "vulnerable": f.get("vulnerable", ""), "patched": f.get("patched", ""),
                })
        (ROOT / "benchmarks" / "cve_pairs.json").write_text(json.dumps(pairs, indent=2))
        print(f"pairs   -> benchmarks/cve_pairs.json ({len(pairs)})")
        for r in results:
            for f in r.get("files", []):
                f.pop("vulnerable", None)
                f.pop("patched", None)

    out = ROOT / "benchmarks" / "cve_results.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"results -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
