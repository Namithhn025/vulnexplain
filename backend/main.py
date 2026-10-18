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


def explain_vulns_batch(vulns: list[dict]) -> list[str]:
    """Explain all vulns in a single Gemma 4 call."""
    if not gemini_client:
        return ["Set GEMINI_API_KEY env var to get AI explanations."] * len(vulns)

    vuln_list = ""
    for i, v in enumerate(vulns, 1):
        vuln_list += f"""
{i}. ID: {v['id']} | Package: {v['package']} {v.get('version','')} | Severity: {v['severity']}
   Summary: {v['summary']}
"""

    prompt = f"""You are a security expert. For each vulnerability below, write a 2-3 sentence plain English explanation for a developer.
Cover: what the risk is, what an attacker could do, and how to fix it.

Format your response EXACTLY like this for each one:
1. <explanation here>
2. <explanation here>
... and so on.

Vulnerabilities:
{vuln_list}"""

    try:
        response = gemini_client.models.generate_content(
            model="gemma-4-31b-it",
            contents=prompt,
        )
        text = response.text.strip()
        # Parse numbered responses
        import re
        parts = re.split(r'\n?\d+\.\s+', text)
        parts = [p.strip() for p in parts if p.strip()]
        # Pad if Gemma returned fewer explanations than expected
        while len(parts) < len(vulns):
            parts.append("Explanation unavailable.")
        return parts[:len(vulns)]
    except Exception as e:
        return [f"Gemini explanation unavailable: {e}"] * len(vulns)


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

    # Cap at 15 to keep response fast
    vulns = vulns[:15]
    explanations = explain_vulns_batch(vulns)
    enriched = []
    for v, explanation in zip(vulns, explanations):
        v["explanation"] = explanation
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
