# VulnExplain

> Scan any GitHub repo for vulnerable dependencies. Get plain-English explanations powered by Gemma 4. Know exactly what to fix.

**Live demo:** https://vulnexplain-btbp.onrender.com

![VulnExplain Screenshot](docs/screenshot.png)

---

## The Problem

Every software project depends on open-source packages. Many of those packages have known security vulnerabilities — but developers don't know about them. And even when they find out, CVE reports look like this:

> *"Improper neutralization of special elements used in an OS command"*

Nobody understands that.

## What VulnExplain Does

Give it a GitHub repo URL → it does everything else:

1. **Agent 1 — Fetcher** reads the repo's `requirements.txt` or `package.json` and extracts every package + version
2. **Agent 2 — Scanner** checks all packages against [OSV.dev](https://osv.dev) (Google's open vulnerability database with 50,000+ CVEs)
3. **Agent 3 — Explainer** sends each vulnerability to **Gemma 4** which explains it in plain English and suggests the exact fix command

**Example output for Django 1.8.3:**
```
GHSA-3f2c-jm6v-cr35 [XSS]
This vulnerability allows attackers to inject malicious scripts via the
admin interface, stealing session cookies or sensitive user data.
FIX: pip install Django>=4.2.0
```

## Architecture

```
GitHub Repo URL
      │
      ▼
┌─────────────────┐
│  Agent 1        │  Fetches requirements.txt / package.json
│  Fetcher        │  Parses package names + versions
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Agent 2        │  Batch queries OSV.dev API
│  Scanner        │  Returns all known CVEs per package
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Agent 3        │  Calls Gemma 4 (gemma-4-26b-a4b-it)
│  Explainer      │  Plain English explanation + exact fix
└────────┬────────┘
         │
         ▼
  Prioritized vulnerability report
  (Critical → High → Medium → Low)
```

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI |
| Vulnerability Data | OSV.dev API (free, no key needed) |
| AI Explanations | Gemma 4 via Gemini API |
| Frontend | Vanilla HTML/CSS/JS |
| Deployment | Render |

## How to Run Locally

```bash
git clone https://github.com/Namithhn025/vulnexplain.git
cd vulnexplain
GEMINI_API_KEY=your_key_here ./start.sh
```

Open http://localhost:8000 and paste any public GitHub repo URL.

**Get a free Gemini API key:** https://aistudio.google.com

## Supported Languages

| File | Ecosystem |
|---|---|
| `requirements.txt` | Python / PyPI |
| `package.json` | Node.js / npm |

## Example Repos to Scan

```
https://github.com/nVisium/django.nV       # Python — 46 vulns
https://github.com/OWASP/NodeGoat          # Node.js — dozens of vulns
```

## Hackathon

Built for **Hacktoberfest Hack Day Bengaluru 2026**
- **Track:** Track 2 — Best Open-Source AI Project (O3: Trustworthy and Verifiable AI)
- **Team:** TheCockroaches
- **Event:** 18 October 2026, Startup Park, Bengaluru

## License

MIT
