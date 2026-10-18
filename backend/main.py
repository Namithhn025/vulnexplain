"""
VulnExplain — FastAPI backend
Scans a GitHub repo's dependencies against OSV.dev,
then uses Gemini to explain each vulnerability in plain English.
"""

import os
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from google import genai
from google.genai import types as genai_types
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


class ScanRequest(BaseModel):
    repo_url: str


def explain_vuln_with_gemini(vuln: dict) -> str:
    if not gemini_client:
        return "Set GEMINI_API_KEY env var to get AI explanations."

    prompt = f"""You are a security expert. Explain this vulnerability in plain English for a developer who is not a security expert.
Keep it under 4 sentences. Be practical — tell them what could go wrong and what to do.

Package: {vuln['package']} {vuln.get('version', '')} ({vuln['ecosystem']})
CVE/ID: {vuln['id']}
Summary: {vuln['summary']}
Severity: {vuln['severity']}

Explain:
1. What this vulnerability actually means in plain terms
2. What an attacker could do if it's exploited
3. The simplest fix (upgrade version, etc.)"""

    try:
        response = gemini_client.models.generate_content(
            model="gemma-3-27b-it",
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        return f"Gemini explanation unavailable: {e}"


@app.get("/health")
def health():
    return {"ok": True, "gemini_configured": bool(GEMINI_API_KEY)}


@app.post("/scan")
def scan_repo(req: ScanRequest):
    packages, file_type = get_packages_from_repo(req.repo_url)

    if not packages:
        raise HTTPException(
            status_code=404,
            detail=f"No supported dependency file found in {req.repo_url}. Supported: requirements.txt, package.json",
        )

    vulns = check_osv(packages)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda v: severity_order.get(v["severity"].upper(), 4))

    enriched = []
    for v in vulns:
        v["explanation"] = explain_vuln_with_gemini(v)
        enriched.append(v)

    return {
        "repo_url": req.repo_url,
        "dependency_file": file_type,
        "total_packages_scanned": len(packages),
        "vulnerabilities_found": len(enriched),
        "vulnerabilities": enriched,
    }


# Serve frontend
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
