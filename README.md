<div align="center">
  <img src="https://img.shields.io/badge/Status-Production_Ready-success?style=for-the-badge&logo=appveyor" />
  <img src="https://img.shields.io/badge/Python-3.13+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-Waitress_WSGI-black?style=for-the-badge&logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/Machine_Learning-Scikit_Learn-orange?style=for-the-badge&logo=scikit-learn&logoColor=white" />
</div>

<h1 align="center">🛡️ SecOpsAI: Threat Analysis & Adaptive Security Engine</h1>

<p align="center">
  <strong>An enterprise-grade, concurrent vulnerability scanner powered by Machine Learning and deeply integrated with zero-day heuristics.</strong>
</p>

## ✨ Executive Summary

Traditional vulnerability scanners rely heavily on static regular expressions, leading to massive false-positives and agonizingly slow execution times. **SecOpsAI** bridges the gap between offensive security engineering and data science. 

By employing **Scikit-Learn's IsolationForest**, strict DOM-parsing reflection verification (`BeautifulSoup4`), and extreme multi-threaded active-network payloads, this engine dynamically evaluates real-world web applications in a fraction of a second.

## 🚀 Key Enterprise Features

- 🧠 **Machine Learning Anomaly Detection:** Utilizes TF-IDF string vectorization mapped against a localized baseline of standard network topologies to automatically isolate structural zero-day variations.
- 🏎️ **Concurrent Active Scanning:** Ditches linear operations. SecOpsAI unleashes Python's native `ThreadPoolExecutor` to globally saturate target paths with advanced simulated requests, cutting wait-times by 90%.
- 🕸️ **Advanced DOM-Reflection Verification:** No more false-positive vulnerabilities. We intercept active HTTP bodies and meticulously query the Document Object Model to scientifically prove whether an injected payload evaded target sanitization.
- 📡 **Global CVE Intelligence Polling:** Silently traverses backend public intelligence pipelines (e.g., MITRE/CIRCL API) delivering live contextual 0-day threat databases dynamically to your Command Center.
- 📊 **Beautiful Executive Analytics:** Rendered strictly with premium dark-mode aesthetics. Generate interactive `Chart.js` trendlines tracking algorithmic resilience, and instantly export beautiful corporate compliance PDF reports utilizing native JS rendering.

## ⚙️ Architecture & Stack

| Computational Layer | Technology Used | Implementation Purpose |
| ------ | ------ | ------ |
| **Frontend UI/UX** | Vanilla JS, CSS3, Chart.js | Zero-latency, highly optimized Single Page Application. |
| **Backend Core** | Python (Flask), `requests` | High-fidelity payload dispatching and pipeline orchestration. |
| **Data Engine** | Scikit-Learn | Sub-boundary density anomaly clustering and heuristic mitigation. |
| **Validation Context** | BeautifulSoup4 | Active 403 bypass parsing and string-reflection extraction. |
| **Database Persistence** | SQLite & Flask-SQLAlchemy | Instant, localized Threat Archival and Telemetry Querying. |
| **Production Server** | Waitress (WSGI), Flask-Login | Multi-threaded traffic pools wrapped in PBKDF2 Session Access. |

## 🕹️ Quickstart & Deployment

SecOpsAI natively ships with its own robust WSGI distribution layer (`Waitress`), permanently eliminating the insecure footprint of typical dummy-servers.

1. **Clone the Framework**
   ```bash
   git clone https://github.com/AtharvaMeherkar/secops-ai-threat-analyzer.git
   cd secops-ai-threat-analyzer
   ```

2. **Acquire Intelligence Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Ignite the Server (Production Config)**
   ```bash
   python run_prod.py
   ```

4. Navigate to `http://localhost:8080`, log into the central gate using the default super-admin (`admin / admin123`), and commence targeting.

<hr/>

<p align="center">
<i>Engineered specifically for rapid bug-bounty enumeration and defensive security posturing. Do not deploy structural network arrays against servers without explicit authorization.</i>
</p>
