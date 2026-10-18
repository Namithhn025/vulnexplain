"""
Dependency scanner — fetches package list from a GitHub repo
and checks each against OSV.dev for known vulnerabilities.
"""

import requests
import json
import re

SUPPORTED_FILES = ["requirements.txt", "package.json", "pom.xml"]

def fetch_file(repo_url: str, filename: str) -> str | None:
    """Convert GitHub repo URL to raw content URL and fetch file."""
    # https://github.com/owner/repo -> owner/repo
    match = re.match(r"https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", repo_url)
    if not match:
        return None
    path = match.group(1)
    raw_url = f"https://raw.githubusercontent.com/{path}/HEAD/{filename}"
    resp = requests.get(raw_url, timeout=10)
    return resp.text if resp.status_code == 200 else None


def parse_requirements_txt(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # e.g. requests==2.28.0 or requests>=2.0
        parts = re.split(r"[=><~!]+", line)
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else None
        packages.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return packages


def parse_package_json(content: str) -> list[dict]:
    packages = []
    try:
        data = json.loads(content)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        for name, ver in deps.items():
            version = ver.lstrip("^~>=<").split(" ")[0]
            packages.append({"name": name, "version": version, "ecosystem": "npm"})
    except json.JSONDecodeError:
        pass
    return packages


def get_packages_from_repo(repo_url: str) -> tuple[list[dict], str]:
    """Returns (packages, detected_file_type)."""
    content = fetch_file(repo_url, "requirements.txt")
    if content:
        return parse_requirements_txt(content), "requirements.txt"

    content = fetch_file(repo_url, "package.json")
    if content:
        return parse_package_json(content), "package.json"

    return [], "none"


def check_osv(packages: list[dict]) -> list[dict]:
    """Batch-query OSV.dev for vulnerabilities."""
    if not packages:
        return []

    queries = []
    for pkg in packages:
        q = {"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]}}
        if pkg.get("version"):
            q["version"] = pkg["version"]
        queries.append(q)

    resp = requests.post(
        "https://api.osv.dev/v1/querybatch",
        json={"queries": queries},
        timeout=15,
    )
    resp.raise_for_status()
    results = resp.json().get("results", [])

    vulns = []
    for pkg, result in zip(packages, results):
        for v in result.get("vulns", []):
            vulns.append({
                "package": pkg["name"],
                "version": pkg.get("version"),
                "ecosystem": pkg["ecosystem"],
                "id": v.get("id"),
                "summary": v.get("summary", "No summary available"),
                "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
                "references": [r.get("url") for r in v.get("references", [])[:2]],
            })
    return vulns
