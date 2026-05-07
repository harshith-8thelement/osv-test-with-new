"""
OSV Scanner -> GitHub Issues
============================
Strategy:
  - One GitHub issue per vulnerable PACKAGE (not per CVE)
  - Deduplicates PYSEC/GHSA/CVE aliases of the same advisory
  - Picks the highest CVSS score across all advisories   -> severity label
  - Picks the highest STABLE fixed version via semver    -> recommended upgrade
    (pre-release versions like -beta, -rc, -alpha are excluded)
  - Skips if an open issue for that package already exists
  - Filters only HIGH / CRITICAL (CVSS >= 7.0)
  - No emojis in output
  - Full advisory list shown (no truncation)
"""

import json
import os
import re
import requests
from collections import defaultdict
from packaging.version import Version, InvalidVersion

# ---- Config ------------------------------------------------------------------
GITHUB_TOKEN   = os.environ["GITHUB_TOKEN"]
REPO           = os.environ["REPO"]
CVSS_THRESHOLD = 7.0   # HIGH >= 7.0, CRITICAL >= 9.0

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept":        "application/vnd.github+json",
}

# ---- Severity helpers --------------------------------------------------------
def cvss_to_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"

# ---- Semver helpers ----------------------------------------------------------
def safe_version(v: str):
    """Parse version safely; return None on failure."""
    try:
        return Version(v)
    except (InvalidVersion, TypeError):
        return None

def is_stable(v: str) -> bool:
    """Return True only if the version string is a stable release (no pre-release)."""
    parsed = safe_version(v)
    if parsed is None:
        return False
    return not parsed.is_prerelease and not parsed.is_devrelease

def max_stable_version(versions: list[str]) -> str:
    """
    Return the highest STABLE semver string from a list.
    Pre-releases (-beta, -rc, -alpha, .devN, etc.) are excluded.
    Falls back to highest overall version if no stable versions exist.
    """
    stable = [v for v in versions if v and v != "N/A" and is_stable(v)]
    all_   = [v for v in versions if v and v != "N/A"]

    pool = stable if stable else all_

    parsed = [(safe_version(v), v) for v in pool]
    valid  = [(pv, raw) for pv, raw in parsed if pv is not None]
    if not valid:
        return "N/A"
    return max(valid, key=lambda x: x[0])[1]

# ---- GitHub helpers ----------------------------------------------------------
def get_existing_issue_packages() -> set[str]:
    """
    Fetch all open issue titles and extract package names
    from our title format:  [<pkg>] <n> vulnerabilities ...
    """
    pkg_set = set()
    page    = 1

    while True:
        url = (
            f"https://api.github.com/repos/{REPO}/issues"
            f"?state=open&per_page=100&page={page}"
        )
        res = requests.get(url, headers=HEADERS)

        if res.status_code != 200:
            print("Error fetching issues:", res.text)
            break

        issues = res.json()
        if not issues:
            break

        for issue in issues:
            title = issue.get("title", "")
            m = re.match(r"^\[([^\]]+)\]", title)
            if m:
                pkg_set.add(m.group(1).lower())

        page += 1

    return pkg_set


def create_issue(title: str, body: str):
    url  = f"https://api.github.com/repos/{REPO}/issues"
    data = {"title": title, "body": body}
    res  = requests.post(url, headers=HEADERS, json=data)

    if res.status_code != 201:
        print(f"  Failed to create issue: {res.status_code} {res.text}")
    else:
        print(f"  Created: {title}")

# ---- OSV alias deduplication -------------------------------------------------
def canonical_id(vuln: dict) -> str:
    """
    Return a single canonical ID per advisory.
    Prefer CVE -> GHSA -> PYSEC -> osv_id
    """
    osv_id  = vuln.get("id", "")
    aliases = vuln.get("aliases", [])
    all_ids = [osv_id] + aliases

    for aid in all_ids:
        if aid.startswith("CVE-"):
            return aid
    for aid in all_ids:
        if aid.startswith("GHSA-"):
            return aid
    return osv_id

def all_ids_for_vuln(vuln: dict) -> list[str]:
    """Return all IDs (primary + aliases) for display, deduped, order preserved."""
    osv_id  = vuln.get("id", "")
    aliases = vuln.get("aliases", [])
    return list(dict.fromkeys([osv_id] + aliases))

# ---- Extract fixed version from OSV affected[] -------------------------------
def extract_fixed_versions(vuln: dict) -> list[str]:
    versions = []
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    versions.append(event["fixed"])
    return versions

# ---- Extract CVSS score ------------------------------------------------------
def extract_cvss(vuln: dict) -> float | None:
    """
    OSV stores CVSS in multiple places depending on the advisory source.
    Try them all in order of preference.
    """
    severity_map = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0}

    # 1. severity[] array - CVSS v3 numeric score
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        try:
            return float(score_str)
        except (ValueError, TypeError):
            pass
        m = re.search(r"(\d+\.\d+)$", score_str)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass

    # 2. database_specific.severity label fallback
    db_sev = vuln.get("database_specific", {}).get("severity", "").upper()
    if db_sev in severity_map:
        return severity_map[db_sev]

    return None

# ---- Build issue body --------------------------------------------------------
def build_issue_body(
    pkg_name:    str,
    current_ver: str,
    fix_version: str,
    max_cvss:    float,
    source:      str,
    advisories:  list[dict],
) -> str:
    severity_label = cvss_to_label(max_cvss)
    total          = len(advisories)

    # Sort advisories by CVSS descending
    advisories_sorted = sorted(
        advisories,
        key=lambda a: a["cvss"] if a["cvss"] is not None else 0,
        reverse=True,
    )

    # Full advisory table - no truncation
    table_rows = ""
    for adv in advisories_sorted:
        primary_id = adv["ids"][0]
        cvss_str   = f"{adv['cvss']:.1f}" if adv["cvss"] is not None else "N/A"
        fixed_str  = adv["fixed"] or "N/A"
        aliases    = ", ".join(adv["ids"][1:]) if len(adv["ids"]) > 1 else "-"
        table_rows += f"| [{primary_id}]({adv['url']}) | {cvss_str} | {fixed_str} | {aliases} |\n"

    # Full references list - no truncation
    ref_lines = ""
    for adv in advisories_sorted:
        ref_lines += f"- {adv['url']}\n"

    # Remediation snippet based on source
    if source == "requirements.txt":
        remediation = f"""```bash
# requirements.txt
{pkg_name}>={fix_version}

# pip
pip install "{pkg_name}>={fix_version}"
```"""
    elif source == "poetry.lock":
        remediation = f"""```bash
# pyproject.toml
poetry add {pkg_name}@^{fix_version}
poetry lock
poetry install
```"""
    elif source in ("package.json", "package-lock.json", "yarn.lock"):
        remediation = f"""```bash
# npm
npm install {pkg_name}@{fix_version}

# yarn
yarn add {pkg_name}@^{fix_version}
```"""
    else:
        remediation = f"Upgrade `{pkg_name}` to `>= {fix_version}`"

    body = f"""## Security Vulnerabilities in `{pkg_name}`

| Field | Value |
|-------|-------|
| **Package** | `{pkg_name}` |
| **Current Version** | `{current_ver}` |
| **Recommended Fix** | Upgrade to `{fix_version}` |
| **Highest Severity** | {severity_label} (CVSS {max_cvss:.1f}) |
| **Total Advisories** | {total} |
| **Source** | `{source}` |

---

## Advisories

| Advisory ID | CVSS | Fixed In | Aliases |
|-------------|------|----------|---------|
{table_rows}
> Aliases shown where PYSEC / GHSA / CVE refer to the same vulnerability.

---

## References

{ref_lines}
---

## Remediation

{remediation}

> Upgrading to `{fix_version}` resolves ALL {total} listed advisories.
> This issue was auto-generated by [OSV Scanner](https://google.github.io/osv-scanner/).
> It will be skipped on future scans once the package is upgraded and this issue is closed.
"""
    return body

# ---- Main --------------------------------------------------------------------
def main():
    try:
        with open("osv-results.json") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("osv-results.json not found - nothing to process.")
        return

    existing_packages = get_existing_issue_packages()
    print(f"Found {len(existing_packages)} packages with open issues - will skip these.")

    # Group vulnerabilities by (package_name, source)
    pkg_vulns: dict[tuple, dict] = defaultdict(lambda: {
        "current_version": "unknown",
        "advisories": {},
    })

    for result in data.get("results", []):
        source_path = result.get("source", {}).get("path", "unknown")

        if "poetry.lock" in source_path:
            source = "poetry.lock"
        elif "package-lock.json" in source_path:
            source = "package-lock.json"
        elif "yarn.lock" in source_path:
            source = "yarn.lock"
        elif "package.json" in source_path:
            source = "package.json"
        elif "requirements.txt" in source_path:
            source = "requirements.txt"
        else:
            source = os.path.basename(source_path)

        for pkg_entry in result.get("packages", []):
            pkg_info    = pkg_entry.get("package", {})
            pkg_name    = pkg_info.get("name", "unknown")
            current_ver = pkg_info.get("version", "unknown")

            key = (pkg_name, source)
            pkg_vulns[key]["current_version"] = current_ver

            for vuln in pkg_entry.get("vulnerabilities", []):
                cvss = extract_cvss(vuln)

                # Filter: only HIGH / CRITICAL
                if cvss is None or cvss < CVSS_THRESHOLD:
                    continue

                canon = canonical_id(vuln)

                # Dedup by canonical ID
                if canon in pkg_vulns[key]["advisories"]:
                    continue

                fixed_versions = extract_fixed_versions(vuln)
                best_fixed     = max_stable_version(fixed_versions) if fixed_versions else "N/A"
                osv_id         = vuln.get("id", "")
                all_ids        = all_ids_for_vuln(vuln)

                pkg_vulns[key]["advisories"][canon] = {
                    "ids":     all_ids,
                    "cvss":    cvss,
                    "fixed":   best_fixed,
                    "url":     f"https://osv.dev/{osv_id}",
                    "summary": vuln.get("summary", ""),
                }

    # Create one issue per (package, source)
    for (pkg_name, source), info in pkg_vulns.items():
        advisories = list(info["advisories"].values())

        if not advisories:
            continue

        if pkg_name.lower() in existing_packages:
            print(f"Skipping {pkg_name} - open issue already exists.")
            continue

        current_ver = info["current_version"]

        max_cvss = max(
            (adv["cvss"] for adv in advisories if adv["cvss"] is not None),
            default=0.0,
        )

        all_fixed   = [adv["fixed"] for adv in advisories if adv["fixed"] != "N/A"]
        fix_version = max_stable_version(all_fixed)

        severity_label = cvss_to_label(max_cvss)
        total          = len(advisories)

        title = (
            f"[{pkg_name}] {total} {'vulnerability' if total == 1 else 'vulnerabilities'} found"
            f" - upgrade to {fix_version}"
            f" (max CVSS: {max_cvss:.1f} {severity_label})"
        )

        body = build_issue_body(
            pkg_name    = pkg_name,
            current_ver = current_ver,
            fix_version = fix_version,
            max_cvss    = max_cvss,
            source      = source,
            advisories  = advisories,
        )

        print(f"\nCreating issue for [{pkg_name}] ({total} advisories, CVSS {max_cvss:.1f})...")
        create_issue(title, body)


if __name__ == "__main__":
    main()