"""Build a reproducible, explicitly unverified C/C++ vulnerability candidate set.

Source: NVD CVE API v2.0. Run from any working directory with Python 3.9+.
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TARGETS = {
    "null_pointer_dereference": [("CWE-476", 100)],
    "buffer_out_of_bounds": [("CWE-125", 50), ("CWE-787", 50)],
    "use_after_free": [("CWE-416", 100)],
}
EXCLUDE = re.compile(r"\b(java|javascript|python|php|ruby|rust|golang|go language|c#|swift|kotlin|typescript|android app|wordpress plugin)\b", re.I)
NATIVE = re.compile(r"\b(c\+\+|c language|c code|linux kernel|ffmpeg|imagemagick|lib[a-z0-9_-]+|openssl|openbsd|freebsd|webkit|chromium|firefox|qt|sqlite|curl|qemu|wireshark|ghostscript|poppler|binutils|glibc|nginx|apache http|mysql|mariadb|postgresql|php interpreter|node\.js|v8 engine|xpdf|openjpeg|libreoffice|tcpdump|exiv2|jasper|zephyr|expat|kicad|7-zip|openexr|freerdp|hashcat|scribus|capstone|keepassxc|postgis)\b|\.(?:c|cc|cpp|cxx)\b", re.I)
PATCH = re.compile(r"(github\.com/.+/(commit|pull)/|gitlab\.com/.+/(commit|-/commit)/|git\.kernel\.org/.+/c/|sourceware\.org/git/|chromium\.googlesource\.com/.+\+/)", re.I)
INDICATORS = {
    "null_pointer_dereference": re.compile(r"null (pointer )?dereferenc|dereferenc(e|ing) (a )?null", re.I),
    "buffer_out_of_bounds": re.compile(r"out.of.bounds (read|write|access)|buffer (over.read|over.flow)|heap.buffer.overflow|stack.buffer.overflow", re.I),
    "use_after_free": re.compile(r"use.after.free|use after free", re.I),
}
UAF_CONCURRENCY = re.compile(r"\b(race|thread|worker|concurrent|asynchron(?:ous|ously)?|interrupt|rcu|timer)\b", re.I)


def fetch(cwe: str) -> tuple[list[dict], str]:
    # A recent window improves the chance that the CVE record includes upstream fixes.
    total_url = API + "?" + urllib.parse.urlencode({"cweId": cwe, "resultsPerPage": 1})
    with urllib.request.urlopen(total_url, timeout=60) as response:
        total = json.load(response)["totalResults"]
    time.sleep(7)
    start = max(0, total - 1800)
    url = API + "?" + urllib.parse.urlencode({"cweId": cwe, "resultsPerPage": min(2000, total - start), "startIndex": start})
    with urllib.request.urlopen(url, timeout=120) as response:
        data = json.load(response)
    return [x["cve"] for x in data["vulnerabilities"]], url


def description(cve: dict) -> str:
    return next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")


def select(records: list[dict], category: str, count: int, used_ids: set[str]) -> list[dict]:
    result = []
    local_ids: set[str] = set()
    for cve in reversed(records):
        desc = description(cve)
        if cve["id"] in used_ids or cve["id"] in local_ids:
            continue
        refs = cve.get("references", [])
        patches = [r["url"] for r in refs if PATCH.search(r["url"])]
        if cve.get("vulnStatus") in {"Rejected", "Rejected or Withdrawn"}:
            continue
        if not INDICATORS[category].search(desc) or EXCLUDE.search(desc) or not NATIVE.search(desc) or not patches:
            continue
        if category == "use_after_free" and UAF_CONCURRENCY.search(desc):
            continue
        result.append((cve, desc, patches))
        local_ids.add(cve["id"])
        if len(result) == count:
            break
    return result


def main() -> None:
    cache = ROOT / "_nvd_cache"
    cache.mkdir(exist_ok=True)
    used_ids: set[str] = set()
    summary = {}
    for category, cwes in TARGETS.items():
        folder = ROOT / category
        folder.mkdir(exist_ok=True)
        rows = []
        for cwe, needed in cwes:
            cached = cache / f"{cwe}.json"
            if cached.exists():
                payload = json.loads(cached.read_text(encoding="utf-8"))
            else:
                records, query = fetch(cwe)
                payload = {"query": query, "records": records}
                cached.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
                time.sleep(7)
            selected = select(payload["records"], category, needed, used_ids)
            if len(selected) < needed:
                raise RuntimeError(f"{cwe}: only {len(selected)} selected, need {needed}")
            for cve, desc, patches in selected:
                cve_id = cve["id"]
                if cve_id in used_ids:
                    raise RuntimeError(f"duplicate {cve_id}")
                used_ids.add(cve_id)
                record = {
                    "id": cve_id,
                    "category": category,
                    "cwe": cwe,
                    "status": "candidate_source_and_patch_not_independently_audited",
                    "nvd_status": cve.get("vulnStatus"),
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "description": desc,
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "cve_url": f"https://www.cve.org/CVERecord?id={cve_id}",
                    "patch_candidates": patches,
                    "source_language_basis": "native-project keyword in NVD description; source file must be checked",
                    "review_required": [
                        "confirm upstream vulnerable and fixed revisions and C/C++ source",
                        "identify exact object, operation, and reachable trigger path",
                        "verify patch interrupts the same root cause and deduplicate source group",
                    ],
                }
                if category == "null_pointer_dereference":
                    record["review_required"].extend(["identify nullable source contract", "confirm checked value is the value dereferenced"])
                elif category == "buffer_out_of_bounds":
                    record["access_direction"] = "read" if cwe == "CWE-125" else "write"
                    record["review_required"].extend(["confirm actual read/write direction", "record buffer identity, capacity, offset, access width, and units"])
                else:
                    record["review_required"].extend(["confirm explicit free and subsequent use of same allocation", "confirm single-thread event order and no intervening reallocation"])
                (folder / f"{cve_id}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                rows.append({"id": cve_id, "cwe": cwe, "status": record["status"], "file": f"{cve_id}.json"})
        (folder / "index.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        listed = {row["file"] for row in rows}
        for old_file in folder.glob("CVE-*.json"):
            if old_file.name not in listed:
                old_file.unlink()
        summary[category] = {"count": len(rows), "cwe_counts": {cwe: sum(x["cwe"] == cwe for x in rows) for cwe, _ in cwes}}
    (ROOT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
