# 🛡️ SecureOps AI: Autonomous Vulnerability Remediation Planner

> **An intelligent, resource-aware vulnerability remediation planning platform for modern cybersecurity teams.**  
> Built for hackathons, security engineers, and SecOps leads to bridge CVSS severity, asset business context, live threat intelligence (EPSS, CISA KEV), and engineering sprint capacity into an auditable, prioritized remediation schedule.

---

## 🌟 Key Features

1. **Deterministic Risk Scoring Engine**:
   - Transparent, verifiable mathematical calculation combining CVSS v3, Asset Criticality (Critical, High, Medium, Low), Internet Exposure, CISA Known Exploited Vulnerabilities (KEV), EPSS probabilities, and exploit evidence.
   - Generates exact step-by-step arithmetic explanations for every CVE score (0 to 100).
   - Configurable P1–P4 priority cutoffs with automated emergency overrides for active wild exploits.

2. **Resource-Aware Remediation Planning**:
   - Optimizes remediation allocations against actual team capacity hours, hourly engineering costs, and maintenance windows (Emergency, Off-Hours, Weekend, Anytime).
   - Classifies items into 4 distinct quadrants:
     - 🚨 **Immediate Fixes**: Emergency critical threats and active exploits.
     - ⚡ **Quick Wins**: High impact, minimal effort ($\le 3.0$ hours) delivering maximum risk reduction per hour spent.
     - 📅 **Scheduled Fixes**: Substantial vulnerabilities scheduled into standard sprint maintenance windows.
     - 👁️ **Monitor / Verify**: Low risk, compensating controls, or deferred items pending vendor patches.
   - Calculates **Before vs. After Risk Comparison** (Baseline Mean Risk $\to$ Residual Mean Risk, Projected Risk Reduction %).

3. **Data Provenance & Integrity**:
   - Explicitly distinguishes between **SUPPLIED**, **DERIVED**, and **UNAVAILABLE** threat data.
   - **Never hallucinates or fabricates live threat intelligence**: missing EPSS or CISA KEV data is safely defaulted and auditably tagged.

4. **Security & Human-in-the-Loop Governance**:
   - **Zero Shell Execution**: No automated code execution or unsanctioned network patching.
   - **Mandatory Human Lead Approval Gate**: Sign-off workflow for all planned fixes.
   - Secure upload validation with strict file size limits (5 MB) and row caps (2,000 rows).

5. **Dual-Mode AI Briefing (Google Gen AI SDK & Offline Fallback)**:
   - Uses the official Google Gen AI Python SDK (`google-genai`, `gemini-2.5-flash`) for executive briefings when `GEMINI_API_KEY` is present.
   - **100% functional offline**: Automatically falls back to a deterministic rule-based executive briefing engine when the key is omitted.
   - Zero key leakage in UI or logs; secrets managed via `.env`.

6. **Interactive Visual Dashboard**:
   - Built with Streamlit and Plotly.
   - Interactive Priority Pie charts, Category Bar charts, and Risk-vs-Effort Quadrant Scatter plots.
   - Downloadable CSV remediation schedules, Executive Markdown Reports, and Cryptographic JSON Audit Manifests.

---

## 📐 Scoring Formula & Mathematical Model

$$\text{Base Impact} = \text{CVSS} \times 6.5$$

$$\text{Contextual Score} = \text{Base Impact} \times M_{\text{criticality}} \times M_{\text{exposure}}$$

$$\text{Threat Boosters} = B_{\text{CISA}} + (\text{EPSS} \times 20.0) + B_{\text{exploit}}$$

$$\text{Final Risk Score} = \operatorname{Clamp}\left(\text{Contextual Score} + \text{Threat Boosters},\ 0.0,\ 100.0\right)$$

- **Asset Criticality ($M_{crit}$)**: Critical (1.35x), High (1.15x), Medium (1.00x), Low (0.75x)
- **Exposure ($M_{expo}$)**: Internet-Exposed (1.30x), Internal (1.00x)
- **Threat Boosters**: CISA KEV (+18.0 pts), EPSS ($EPSS \times 20.0$ pts), Exploit Evidence (Active: +12.0, Weaponized: +8.0, PoC: +4.0, None: 0.0)

---

## 📁 Project Structure

```text
Prompt var26/
├── app.py                     # Streamlit Cybersecurity Web Dashboard
├── requirements.txt           # Python dependencies
├── .env.example               # Template for optional Gemini API key
├── .gitignore                 # Secrets & temporary file exclusions
├── README.md                  # System documentation & setup guide
├── data/
│   └── synthetic_sample_cves.csv  # 28 realistic synthetic vulnerability profiles
├── src/
│   ├── __init__.py
│   ├── schemas.py             # Schema validation, security bounds, data provenance
│   ├── scoring.py             # Deterministic risk engine & mathematical proof generator
│   ├── planner.py             # Resource-constrained knapsack & sprint allocation engine
│   ├── gemini_service.py      # Google Gen AI SDK integration & offline fallback
│   └── utils.py               # Export helpers (CSV, Markdown, JSON) & sample generator
└── tests/
    ├── __init__.py
    ├── test_scoring.py        # Scoring formulas, clamping bounds, priority classifications
    ├── test_validation.py     # Schema validation, file size limits, malformed inputs
    ├── test_planner.py        # Sprint capacity limits, quadrant allocation, risk reduction
    ├── test_gemini_fallback.py# Verification that app functions offline without Gemini key
    └── test_export.py         # CSV and JSON audit manifest export verification
```

---

## 🚀 Quickstart Guide for Windows

Follow these simple steps in **PowerShell** or **Command Prompt**:

### 1. Open Terminal and Navigate to Directory
```powershell
cd "c:\Users\SIDDHI BHINTADE\Desktop\Prompt var26"
```

### 2. (Optional) Create and Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. (Optional) Configure Gemini API Key
If you want AI-assisted executive briefings, copy `.env.example` to `.env` and insert your Gemini API Key:
```powershell
Copy-Item .env.example .env
```
Open `.env` in any text editor and set:
```text
GEMINI_API_KEY=your_actual_gemini_api_key_here
```
> **Note**: If you skip this step, the app will run smoothly in **Offline Fallback Mode** with zero warnings or errors.

### 5. Run the Automated Test Suite
Verify that all unit tests pass:
```powershell
python -m pytest tests/ -v
```

### 6. Launch the Streamlit Dashboard
```powershell
python -m streamlit run app.py
```
*(Or `streamlit run app.py` if python scripts are already in your Windows PATH)*
Streamlit will automatically open your default browser at `http://localhost:8501`.

---

## 🧪 CSV Upload Format Specifications

When uploading custom CSV datasets, the following schema is supported:

| Column Header | Type | Required? | Accepted Values / Description |
| :--- | :--- | :--- | :--- |
| `cve_id` | String | **Yes** | e.g. `CVE-2023-34362` (Standard CVE pattern) |
| `cvss_score` | Float | **Yes** | `0.0` to `10.0` |
| `asset_criticality` | String | **Yes** | `Critical`, `High`, `Medium`, `Low` |
| `internet_exposed` | Boolean | **Yes** | `True`/`False`, `Yes`/`No`, `1`/`0` |
| `remediation_effort_hours`| Float | **Yes** | Positive float (e.g. `2.5`, `8.0`) |
| `asset_name` | String | No | e.g. `Prod-Gateway-01` |
| `vulnerability_title` | String | No | Descriptive vulnerability title |
| `epss_score` | Float | No | `0.0` to `1.0` (Defaults to `0.01` if unavailable) |
| `cisa_kev` | Boolean | No | `True`/`False` (Defaults to `False` if unavailable) |
| `exploit_evidence` | String | No | `Active`, `Weaponized`, `PoC`, `None` |
| `maintenance_window` | String | No | `Emergency`, `Off-Hours`, `Weekend`, `Anytime` |
| `patch_available` | Boolean | No | `True`/`False` (Defaults to `True`) |

A ready-to-use sample dataset with 28 realistic vulnerabilities is included in `data/synthetic_sample_cves.csv`.

---

## 🔒 Security & Safe Computing Statement
- SecureOps AI is designed as a **strategic planning tool**. It adheres to the principle of least privilege.
- It **does not** execute remote scripts, open network sockets to vulnerable targets, or apply patches autonomously.
- All actions require formal sign-off by a human security operator.
