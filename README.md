# VulnExplain

An open-source AI tool that scans GitHub repositories for vulnerable dependencies and explains each vulnerability in plain English.

## What it does

Give it a GitHub repo URL → it fetches the dependency file → checks every package against [OSV.dev](https://osv.dev) → uses Gemini AI to explain each vulnerability in plain language, prioritized by severity.

**Supports:** `requirements.txt` (Python/PyPI) and `package.json` (Node/npm)

## Tech Stack

- **Backend:** Python, FastAPI, OSV.dev API, Gemini API (gemma-3-27b-it)
- **Frontend:** Vanilla HTML/CSS/JS

## How to run

```bash
git clone https://github.com/Namithhn025/vulnexplain.git
cd vulnexplain
GEMINI_API_KEY=your_key_here ./start.sh
```

Then open http://localhost:8000

## Built for

Hacktoberfest Hack Day Bengaluru 2026 — Track 2: Best Open-Source AI Project
