# Project Dark Hunt — Dashboard Interface

**Organization:** Team NullX  
**Project Lead:** Rahat Sahriar Rafi  
**Website Developer:** Md. Tanjim Islam  
**Evidence Collection:** MD Rakib Hasan Apon  
**Deadline:** 31 October 2026  
**Operational Mode:** 100% Client-Side Offline (No internet, external APIs, CDNs, or web servers required)

---

## 1. Overview
The Project Dark Hunt dashboard is an offline-capable, evidence-backed cyber threat intelligence application designed to present lawfully gathered public-source OSINT concerning Bangladesh's 45 Key Point Installations (KPIs).

## 2. Directory Structure
```text
dashboard/
├── index.html     # Semantic HTML5 application shell & view templates
├── styles.css     # Professional dark-theme threat-intelligence UI stylesheet
├── app.js         # Vanilla JavaScript application engine, filters, modals, and export gate
├── report.css     # A4 print-optimized stylesheet for executive dossier output
├── data.js        # Self-contained offline JavaScript data bundle (window.PROJECT_DARK_HUNT_DATA)
└── README.md      # Dashboard architecture documentation
```

## 3. How to Launch Offline (Zero Web Server Required)
Because all dataset records, schemas, sources, and evidence metadata are compiled into `dashboard/data.js`, the dashboard does **not** rely on asynchronous `fetch()` calls that are typically restricted by browser security policies under the `file://` scheme.

### Launch via File Manager / Browser:
1. Open your web browser (Chrome, Firefox, Edge, Safari, Chromium).
2. Open `index.html` directly from disk:
   - Double click `dashboard/index.html` in your file manager, or
   - Press `Ctrl + O` in the browser and select `/home/NullX-C/Projects/Project Dark Hunt/dashboard/index.html`.
3. The dashboard will load and initialize in strict offline mode.

### Optional Local Web Server (Convenience Only):
```bash
python3 -m http.server 8080 --directory "dashboard"
# Open http://localhost:8080 in your browser
```

## 4. Primary Views
1. **Overview (KPI Summary):** Complete ledger of Bangladesh's 45 Key Point Installations, dynamic claims counts, criticality levels, highest threat levels, and detailed institutional profiles.
2. **Exposure Search:** Search-first interface across all 68 documented exposure claims, multi-parameter filtering, pagination, modal dossiers, and legal-gate-protected CSV/JSON exports.
3. **Research Source Register:** Catalog of 20 research references, underground directories, and darknet leak platforms. *All onion links are passive and are never crawled or resolved.*
4. **Evidence Registry:** Ledger of 40 visual screenshot artifacts extracted from team research archives, complete with calculated SHA-256 hashes and OCR previews.
5. **Threat & Impact:** Sector-by-sector risk distribution matrix and documented methodology.
6. **Recommended Response:** Defensive incident response protocols mapped to designated operational owners (`CERT`, `LEA`, `operator`).
7. **Print Briefing:** Executive A4 dossier ready for `Print / Save as PDF`.

## 5. Security Safeguards
- **Strict Legal Gate:** Exports fail closed unless `legal_gate_ok === true`.
- **CSV Formula Injection:** Values beginning with `=`, `+`, `-`, `@`, `\t`, or `\r` are sanitized with single-quote escaping.
- **Redaction:** All personal identifiers, phone numbers, emails, and credentials are replaced with `[REDACTED]`.
- **Passive Containment:** Zero network calls, no automated Tor or dark web connections.
