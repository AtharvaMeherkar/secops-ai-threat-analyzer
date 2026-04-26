import time
import random
from datetime import datetime

class SimulationEngine:
    """
    Simulates request payloads for a target URL.
    This safely mocks network traffic to prevent actual unauthorized scanning 
    while demonstrating industrial detection capabilities.
    """
    def __init__(self, target_url):
        self.target_url = target_url
        self.simulated_logs = []

    def _generate_log(self, payload, category, status_code, response_time):
        return {
            "timestamp": datetime.now().isoformat(),
            "target_url": self.target_url,
            "payload": payload,
            "category_simulation": category, # internal conceptual tag
            "status_code": status_code,
            "response_time_ms": response_time
        }

    def simulate_normal_traffic(self):
        """Simulates clean, normal user navigation."""
        endpoints = ['/', '/about', '/contact', '/products?id=12', '/login', '/dashboard', '/api/health']
        sampled_endpoints = random.sample(endpoints, k=random.randint(3, len(endpoints)))
        for ep in sampled_endpoints:
            time.sleep(0.05) # fake network delay
            self.simulated_logs.append(
                self._generate_log(ep, "Normal", 200, random.randint(20, 80))
            )

    def simulate_suspicious_traffic(self):
        """Simulates enumerative or probing behavior."""
        payloads = [
            '/products?id=12 AND 1',
            '/admin',
            '/config.bak',
            '/?search=test%20input',
            '/.env'
        ]
        sampled_payloads = random.sample(payloads, k=random.randint(2, len(payloads)))
        for p in sampled_payloads:
            time.sleep(0.05)
            status = random.choice([404, 403, 301, 200])
            self.simulated_logs.append(
                self._generate_log(p, "Suspicious", status, random.randint(50, 150))
            )

    def simulate_abnormal_traffic(self):
        """Simulates overt, high-risk attack payloads."""
        payloads = [
            "/products?id=1' OR '1'='1",
            "/?q=<script>alert('XSS')</script>",
            "/api/v1/users?id=1; DROP TABLE users;",
            "/download?file=../../../../etc/passwd",
            "/?cmd=cat /etc/shadow"
        ]
        sampled_payloads = random.sample(payloads, k=random.randint(1, len(payloads)))
        for p in sampled_payloads:
            time.sleep(0.05)
            status = random.choice([200, 500, 403, 403, 404]) # Add 403/404 so WAF blocks are simulated more often
            self.simulated_logs.append(
                self._generate_log(p, "High Risk", status, random.randint(100, 300))
            )

    def run_simulation(self):
        """Runs all simulations and returns the combined log traces."""
        self.simulate_normal_traffic()
        self.simulate_suspicious_traffic()
        self.simulate_abnormal_traffic()
        
        # Shuffle to simulate concurrent asynchronous requests
        random.shuffle(self.simulated_logs)
        return self.simulated_logs
