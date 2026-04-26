from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json

from models import db, User, ScanReport
from modules.input_module import validate_url, sanitize_url, InputValidationError
from modules.scanner_engine import ScannerEngine
from modules.detection_engine import DetectionEngine
from modules.classification_engine import ClassificationEngine
from modules.risk_engine import RiskEngine
from modules.advisory_engine import AdvisoryEngine

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SuperSecretProductionKey123!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///production.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create dummy user on startup if not exists
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256')
        new_user = User(username='admin', password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/api/reports', methods=['GET'])
@login_required
def get_reports():
    reports = ScanReport.query.order_by(ScanReport.scan_time.desc()).all()
    output = []
    for r in reports:
        output.append({
            "id": r.id,
            "target": r.target_url,
            "scan_time": r.scan_time.isoformat(),
            "risk_score": r.risk_score,
            "risk_level": r.risk_level
        })
    return jsonify(output)

@app.route('/api/intelligence', methods=['GET'])
@login_required
def get_intelligence():
    # Try fetching real global CVE feed from CIRCL public API
    try:
        import requests
        resp = requests.get("https://cve.circl.lu/api/last", timeout=4)
        if resp.status_code == 200:
            cves = resp.json()
            feed = []
            for item in cves[:5]:
                feed.append({
                    "id": item.get("id", "UNKNOWN"),
                    "threat": item.get("summary", "No description")[:90] + "...",
                    "severity": "CRITICAL" if float(item.get("cvss") or 0) >= 8.0 else "HIGH",
                    "active": True
                })
            return jsonify(feed)
    except Exception as e:
        pass # Fallback triggers if API is offline
        
    # Local fallback
    feed = [
        {"id": "CVE-2023-38408", "threat": "OpenSSH Remote Code Execution (Fallback Feed)", "severity": "CRITICAL", "active": True},
        {"id": "ML-ANOMALY", "threat": "Scikit-Learn Sub-Boundary Density Cluster", "severity": "HIGH", "active": True},
        {"id": "Zero-Day", "threat": "Novel Path Traversal Variant Detected", "severity": "HIGH", "active": True},
        {"id": "CWE-79", "threat": "Cross-Site Scripting (XSS) via injected SVG", "severity": "MEDIUM", "active": False}
    ]
    return jsonify(feed)

@app.route('/api/scan', methods=['POST'])
@login_required
def scan_url():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON payload provided"}), 400
        
    raw_url = data.get('url', '')
    
    try:
        sanitized_url = sanitize_url(raw_url)
        validate_url(sanitized_url)
        
        # Step 1: Active Network Scanner
        scanner = ScannerEngine(sanitized_url)
        raw_logs = scanner.run_active_scan()
        
        # Step 2: Detection (ML + Heuristics)
        detector = DetectionEngine(raw_logs)
        analyzed_logs = detector.analyze()
        
        # Step 3: Classification
        classifier = ClassificationEngine(analyzed_logs)
        classified_logs = classifier.classify()
        
        # Step 4: Risk Scoring
        risk_engine = RiskEngine(classified_logs)
        risk_assessment = risk_engine.calculate_risk()
        
        # Step 5: Advisory
        advisor = AdvisoryEngine(classified_logs, risk_assessment)
        recommendations = advisor.generate_recommendations()
        
        # Step 6: DB Archival (Replaces JSON file ReportingEngine)
        report_data = {
            "metadata": {"target": sanitized_url},
            "executive_summary": {
                "risk_score": risk_assessment['score'],
                "risk_level": risk_assessment['level'],
                "threat_breakdown": risk_assessment['breakdown']
            },
            "advisories": recommendations,
            "detailed_logs": classified_logs
        }
        
        new_report = ScanReport(
            target_url=sanitized_url,
            risk_score=risk_assessment['score'],
            risk_level=risk_assessment['level'],
            report_data=json.dumps(report_data)
        )
        db.session.add(new_report)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "report": report_data
        })
        
    except InputValidationError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"System Error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
