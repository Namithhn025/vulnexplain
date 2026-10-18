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

def explain_one(v: dict) -> tuple[str, str]:
    """Call Gemma 4 for a single vulnerability — reliable, no cutoff."""
    if not gemini_client:
        return "Set GEMINI_API_KEY to get AI explanations.", ""

    ecosystem = v.get("ecosystem", "")
    pkg_cmd = "pip install" if ecosystem == "PyPI" else "npm install"

    prompt = f"""You are a security expert. Explain this vulnerability in 2 plain English sentences for a developer. Then give the fix command.

Package: {v['package']} {v.get('version', '?')} ({ecosystem})
ID: {v['id']}
Summary: {v['summary']}

Reply in exactly this format:
EXPLANATION: <2 sentences on risk and attacker impact>
FIX: <exact command like "{pkg_cmd} {v['package']}>=X.Y.Z">"""

    try:
        response = gemini_client.models.generate_content(model=MODEL, contents=prompt)
        text = response.text.strip()
        exp_match = re.search(r'EXPLANATION:\s*(.+?)(?=\nFIX:|\Z)', text, re.DOTALL)
        fix_match = re.search(r'FIX:\s*(.+)', text)
        explanation = exp_match.group(1).strip() if exp_match else text[:300]
        fix = fix_match.group(1).strip().strip('`') if fix_match else f"Upgrade {v['package']} to the latest version."
        return explanation, fix
    except Exception as e:
        return f"Explanation unavailable: {e}", f"Upgrade {v['package']} to the latest version."


def agent_explainer(vulns: list[dict]) -> list[dict]:
    """Use Gemma 4 to explain top 5 vulns one at a time."""
    top = vulns[:5]
    for v in top:
        v["explanation"], v["fix"] = explain_one(v)
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
