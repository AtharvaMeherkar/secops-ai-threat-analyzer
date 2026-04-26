import requests
import random
from datetime import datetime
import concurrent.futures

# Disable SSL Warnings for Demo active scans against untrusted certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ScannerEngine:
    """
    Active Concurrent Network Scanner.
    Dispatches LIVE HTTP payloads to the target domain concurrently using ThreadPoolExecutor.
    """
    def __init__(self, target_url):
        self.target_url = target_url
        self.scanned_logs = []
        self.headers = {'User-Agent': 'SecOpsAI-Active-Scanner/2.0'}
        self.timeout = 5 # 5 second timeout to prevent hanging

    def _execute_probe(self, payload_item):
        payload = payload_item['path']
        category = payload_item['category']
        
        target = f"{self.target_url}{payload}" if payload.startswith('/') else f"{self.target_url}/{payload}"
        start_time = datetime.now()
        html_body = ""
        
        try:
            response = requests.get(target, headers=self.headers, timeout=self.timeout, verify=False)
            status = response.status_code
            if status == 200:
                html_body = response.text
        except requests.RequestException:
            status = 408
            
        elapsed_time = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "target_url": target,
            "payload": payload,
            "category_simulation": category,
            "status_code": status,
            "response_time_ms": elapsed_time,
            "html_body": html_body
        }

    def run_active_scan(self):
        """Dispatches real network requests concurrently."""
        probes = []
        
        normal_paths = ['/', '/login', '/about', '/api/health']
        for p in random.sample(normal_paths, k=min(2, len(normal_paths))):
            probes.append({'path': p, 'category': 'Normal'})
            
        suspicious_paths = ['/.git/config', '/admin.php', '/config.bak', '/.env']
        for p in random.sample(suspicious_paths, k=min(2, len(suspicious_paths))):
            probes.append({'path': p, 'category': 'Suspicious'})
            
        abnormal_paths = ["/?search=<script>alert('XSS')</script>", "/products?id=1'+OR+'1'='1", "/etc/passwd"]
        for p in random.sample(abnormal_paths, k=min(2, len(abnormal_paths))):
            probes.append({'path': p, 'category': 'High Risk'})
            
        # Fire requests concurrently for aggressive rapid scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(self._execute_probe, probes))
            
        self.scanned_logs.extend(results)
        return self.scanned_logs
