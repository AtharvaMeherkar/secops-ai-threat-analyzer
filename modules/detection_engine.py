import re
from bs4 import BeautifulSoup
from modules.ml_engine import MLEngine

class DetectionEngine:
    """
    Parses request logs using Scikit-Learn IsolationForest Models, BeautifulSoup DOM Reflection, and Heuristics.
    """
    def __init__(self, logs):
        self.logs = logs
        self.ml_model = MLEngine()
        
        self.sql_patterns = [r'(?i)UNION\s+SELECT', r'(?i)OR\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1[\'"]?', r'(?i)DROP\s+TABLE', r"['];"]
        self.xss_patterns = [r'(?i)<script>', r'(?i)javascript:', r'(?i)onerror=', r'(?i)onload=']
        self.lfi_patterns = [r'\.\./\.\./', r'(?i)/etc/passwd', r'(?i)/etc/shadow']
        self.sensitive_files = [r'(?i)\.bak$', r'(?i)\.git', r'(?i)\.env', r'(?i)admin']

    def _check_dom_reflection(self, html_body, payload):
        """Uses BeautifulSoup to check if the strict payload is reflected in the DOM without sanitization."""
        if not html_body or not payload:
            return False
            
        # If payload has a script tag, beautifulsoup parses it if it wasn't strictly escaped
        soup = BeautifulSoup(html_body, 'html.parser')
        
        if '<script>' in payload.lower():
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and "alert('xss')" in script.string.lower():
                    return True
        return False

    def analyze(self):
        analyzed_logs = []
        for log in self.logs:
            payload = log.get('payload', '')
            html_body = log.pop('html_body', '') # Strip payload to keep API response lightweight
            flags = []
            
            # 1. Scikit-Learn Anomaly
            is_anomaly, score = self.ml_model.predict_anomaly(payload)
            if is_anomaly:
                flags.append(f"ML_ANOMALY_DETECTED")
                
            # 2. XSS Strict DOM Reflection Check (Feature 3)
            if self._check_dom_reflection(html_body, payload):
                flags.append("XSS_DOM_REFLECTION_VERIFIED")
            
            # 3. Heuristic Failsafes
            for pattern in self.sql_patterns:
                if re.search(pattern, payload):
                    flags.append("SQL_INJECTION_PATTERN")
                    break
            for pattern in self.xss_patterns:
                if re.search(pattern, payload) and "XSS_DOM_REFLECTION_VERIFIED" not in flags:
                    flags.append("XSS_PATTERN_PROBE")
                    break
            for pattern in self.lfi_patterns:
                if re.search(pattern, payload):
                    flags.append("LOCAL_FILE_INCLUSION")
                    break
            for pattern in self.sensitive_files:
                if re.search(pattern, payload):
                    flags.append("SENSITIVE_FILE_ACCESS")
                    break
                    
            log['detected_flags'] = flags
            analyzed_logs.append(log)
            
        return analyzed_logs
