# CWE Insight — ELE8094 Assignment 2

**Author: Mihir Brijesh Solanki (40481948)**

A secure Python Flask REST API that parses the CWE XML dataset (v4.19.1, 969 weaknesses)
and serves security intelligence to users, including an analysis not available on the CWE website.

## Architecture

```
User → [Flask REST API] ← [Local CWE XML → SQLite cache]
```

The XML is parsed once at startup using `defusedxml` (XXE-safe) and cached in SQLite.
All subsequent requests query the database — no per-request XML parsing.

---

## Quick Start

> Run these commands from inside the `cwe-insight/` folder.

**Step 1 — Create and activate a virtual environment**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

**Step 2 — Install dependencies**

```bash
pip install -r requirements.txt
```

**Step 3 — Start the server**

```bash
python run.py
```

The server starts automatically, parses the CWE XML on first launch (~0.5 s), and caches everything in SQLite. No separate database setup step is needed.

**Step 4 — Open in browser**

```
http://127.0.0.1:5000
```

The web UI lists all available API endpoints with example links you can click directly.

---

## Endpoints

### 1. GET `/api/v1/weaknesses/<cwe_id>`

Returns full details for a single CWE weakness.

**Validation:** `cwe_id` must be integer 1–9999. Double-validated by Flask's `<int:>` converter and the allowlist range check.

```bash
curl http://localhost:5000/api/v1/weaknesses/79
```

**Response shape:**
```json
{
  "cwe_id": 79,
  "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "abstraction": "Base",
  "description": "The product does not neutralize...",
  "extended_description": "",
  "likelihood_of_exploit": "High",
  "consequences": [
    { "scope": "Integrity", "impact": "Execute Unauthorized Code or Commands", "note": "..." }
  ],
  "applicable_platforms": [
    { "type": "Language", "name": "Not Language-Specific", "prevalence": "Undetermined" }
  ],
  "detection_methods": [
    { "method": "Automated Static Analysis", "effectiveness": "Moderate" }
  ]
}
```

**Error responses (always JSON):**
- `400` — ID out of range
- `404` — CWE not found
- `405` — wrong HTTP method

---

### 2. GET `/api/v1/weaknesses/search`

Search weaknesses by platform, likelihood, and/or abstraction. Paginated.

**Accepted parameters (all others rejected with 400):**

| Parameter    | Values                              | Default |
|-------------|--------------------------------------|---------|
| `platform`  | Any string, max 50 chars             | —       |
| `likelihood`| `High`, `Medium`, `Low`              | —       |
| `abstraction`| `Class`, `Base`, `Variant`, `Compound` | —    |
| `limit`     | Integer 1–100                        | 20      |
| `offset`    | Integer ≥ 0                          | 0       |

```bash
curl "http://localhost:5000/api/v1/weaknesses/search?likelihood=High&abstraction=Base&limit=5"
```

**Response shape:**
```json
{
  "total": 42,
  "limit": 5,
  "offset": 0,
  "results": [
    {
      "cwe_id": 22,
      "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
      "abstraction": "Base",
      "likelihood_of_exploit": "High"
    }
  ]
}
```

---

### 3. GET `/api/v1/analysis/consequence-platform-matrix`

**The key insight feature — not available on the CWE website.**

Computes CIA (Confidentiality, Integrity, Availability) impact distributions across all
weaknesses for each platform (Java, Python, C, PHP, JavaScript, etc.), plus the top 3
highest-risk CWEs per platform ranked by distinct consequence scope count.

```bash
curl http://localhost:5000/api/v1/analysis/consequence-platform-matrix
```

**Response shape:**
```json
{
  "metadata": {
    "total_weaknesses_in_dataset": 969,
    "platforms_analysed": ["C", "C++", "Go", "Java", "JavaScript", "PHP"],
    "description": "CIA consequence distribution per platform..."
  },
  "matrix": {
    "Java": {
      "Confidentiality": {
        "Read Application Data": { "count": 15, "percentage": 65.2 }
      },
      "Integrity": {
        "Modify Application Data": { "count": 13, "percentage": 36.1 }
      }
    }
  },
  "top_risks": {
    "Java": [
      {
        "cwe_id": 95,
        "name": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "distinct_consequence_scopes": 4,
        "total_consequence_entries": 5,
        "likelihood_of_exploit": "Medium"
      }
    ]
  }
}
```

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| `defusedxml` instead of `xml.etree.ElementTree` | Prevents XXE injection, Billion Laughs DoS, external DTD loading |
| Parameterised SQL queries throughout | Prevents SQL injection regardless of input source |
| Allowlist input validation | Unknown params rejected; only enumerated values accepted |
| Parse-once, cache-always | Eliminates per-request XML parsing overhead and attack surface |
| Security headers on every response | CSP `default-src 'self'`, `X-Content-Type-Options`, `X-Frame-Options`, HSTS |
| Rate limiting (200/hr global, 10/min analysis) | Mitigates DoS on expensive computation |
| JSON-only error handlers | No HTML error pages; no stack traces exposed |
| Debug mode locked to config | `DEBUG=False` in production config; never hardcoded |

---

## Running Tests

```bash
python3 -m pytest tests/ -v                          # requires pytest
# OR (stdlib only, no install needed):
python3 tests/run_tests.py
```

Test coverage includes:
- Valid and invalid CWE IDs (negative, zero, >9999, string)
- SQL injection attempts via search params
- Unknown/invalid query parameter rejection
- Security header presence
- No stack traces in error responses
- Matrix structure validation

---

## AI Tool Declaration

I used Claude and ChatGPT during this assignment as thinking aids — to talk through ideas, understand concepts, and work out approaches when I was stuck. All the code, design decisions, and implementation were done by me. I did not copy any code from these tools; they helped me think, not write.

---

## DevSecOps Pipeline (`.gitlab-ci.yml`)

| Stage | Tool | Purpose |
|-------|------|---------|
| `test` | pytest | All tests must pass |
| `sast` | bandit | Static security analysis — report saved as CI artifact |
| `dependency-scan` | safety | CVE check on all dependencies |
| `quality` | pytest-cov | Coverage gate: fail if below 70% |
