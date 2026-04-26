# AI-Powered Web Application Threat Detection & Adaptive Security Advisor

An industrial-grade cybersecurity tool designed to simulate, detect, and classify web application threats intuitively. The system utilizes weighted heuristic algorithms (AI-simulation) to score risk levels and generate comprehensive security advisories.

## System Architecture

1. **Input Module**: Validates and sanitizes targets.
2. **Simulation Engine**: Generates safe, mock payload network traffic representing Normal, Suspicious, and High-Risk behavior.
3. **Detection Engine**: Scans payloads using pattern recognition for SQLi, XSS, LFI, and abnormal structures.
4. **Classification Engine**: Labels traits and attaches severity context.
5. **Risk Engine**: Aggregates traits to build a macroscopic 0-100 Security Posture Score.
6. **Advisory Engine**: Maps threats to actionable OWASP mitigation recommendations.
7. **Reporting Engine**: Persists data into timestamped JSON files.
8. **Dashboard UI**: Flask-driven dark-mode command center.

## Running the System

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the engine:
   ```bash
   python app.py
   ```
3. Open `http://localhost:5000` in your browser.
4. Input a target URL and Initiate the Neural Scan.

## Running Tests

Run the full automated test suite to ensure module integrity:
```bash
pytest tests/test_pipeline.py -v
```
