"""
VulnExplain — FastAPI backend
Multi-agent architecture:
  Agent 1 (Fetcher)   — fetches & parses repo dependencies
  Agent 2 (Scanner)   — queries OSV.dev for vulnerabilities
  Agent 3 (Explainer) — Gemma 4 explains top vulns in plain English
"""

import os
import re
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from google import genai
from scanner import get_packages_from_repo, check_osv

app = FastAPI(title="VulnExplain")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
gemini_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
MODEL = "gemma-4-26b-a4b-it"


class ScanRequest(BaseModel):
    repo_url: str


# ── Agent 1: Fetcher ─────────────────────────────────────────────────────────

def agent_fetcher(repo_url: str) -> tuple[list[dict], str]:
    """Fetch and parse dependencies from a GitHub repo."""
    packages, file_type = get_packages_from_repo(repo_url)
    return packages, file_type


# ── Agent 2: Scanner ─────────────────────────────────────────────────────────

def agent_scanner(packages: list[dict]) -> tuple[list[dict], dict]:
    """Query OSV.dev and return all vulns + severity summary."""
    vulns = check_osv(packages)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda v: severity_order.get(v["severity"].upper(), 4))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulns:
        s = v["severity"].upper()
        summary[s if s in summary else "UNKNOWN"] += 1

    return vulns, summary


# ── Agent 3: Explainer ────────────────────────────────────────────────────────

def agent_explainer(vulns: list[dict]) -> list[dict]:
    """Use Gemma 4 to explain top 5 vulns and suggest exact fix versions."""
    top = vulns[:5]

    if not gemini_client:
        for v in top:
            v["explanation"] = "Set GEMINI_API_KEY to get AI explanations."
            v["fix"] = "Check the package's changelog for a patched version."
        return top

    vuln_list = ""
    for i, v in enumerate(top, 1):
        vuln_list += f"{i}. ID: {v['id']} | Package: {v['package']} {v.get('version','?')} | Severity: {v['severity']}\n   Summary: {v['summary']}\n\n"

    prompt = f"""You are a security expert helping developers understand vulnerabilities.

For each vulnerability below, respond with EXACTLY this format:
EXPLANATION: <2-3 plain English sentences — what the risk is and what an attacker could do>
FIX: <one line — the exact upgrade command or version, e.g. "pip install django>=4.2.0" or "npm install express@4.18.2">

---
{vuln_list}
Respond for all {len(top)} vulnerabilities, numbered 1 to {len(top)}."""

    try:
        response = gemini_client.models.generate_content(model=MODEL, contents=prompt)
        text = response.text.strip()

        # Parse each numbered block
        blocks = re.split(r'\n?(?=\d+\.)', text)
        explanations = []
        fixes = []
        for block in blocks:
            if not block.strip():
                continue
            exp_match = re.search(r'EXPLANATION:\s*(.+?)(?=FIX:|$)', block, re.DOTALL)
            fix_match = re.search(r'FIX:\s*(.+?)(?=\n\d+\.|$)', block, re.DOTALL)
            explanations.append(exp_match.group(1).strip() if exp_match else "Explanation unavailable.")
            fixes.append(fix_match.group(1).strip() if fix_match else "Check the package's changelog for a patched version.")

        for i, v in enumerate(top):
            v["explanation"] = explanations[i] if i < len(explanations) else "Explanation unavailable."
            v["fix"] = fixes[i] if i < len(fixes) else "Check the package's changelog for a patched version."

    except Exception as e:
        for v in top:
            v["explanation"] = f"Gemma 4 unavailable: {e}"
            v["fix"] = "Check the package's changelog for a patched version."

    return top


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"ok": True, "gemini_configured": bool(GEMINI_API_KEY), "model": MODEL}


@app.post("/scan")
def scan_repo(req: ScanRequest):
    # Agent 1 — Fetch
    packages, file_type = agent_fetcher(req.repo_url)
    if not packages:
        raise HTTPException(
            status_code=404,
            detail=f"No supported dependency file found. Supported: requirements.txt, package.json",
        )

    # Agent 2 — Scan
    all_vulns, severity_summary = agent_scanner(packages)
    total_vulns = len(all_vulns)

    # Agent 3 — Explain top 5
    explained = agent_explainer(all_vulns)

    return {
        "repo_url": req.repo_url,
        "dependency_file": file_type,
        "total_packages_scanned": len(packages),
        "total_vulnerabilities_found": total_vulns,
        "severity_summary": severity_summary,
        "top_vulnerabilities": explained,
    }


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
