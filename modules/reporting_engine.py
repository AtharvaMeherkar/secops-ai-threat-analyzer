import json
import os
from datetime import datetime

class ReportingEngine:
    """
    Consolidates analysis into formal JSON reports for auditing and persistence.
    """
    def __init__(self, target_url, risk_assessment, recommendations, logs_dump):
        self.target_url = target_url
        self.risk_assessment = risk_assessment
        self.recommendations = recommendations
        self.logs_dump = logs_dump
        
        # Ensure reports directory exists
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_report(self):
        """
        Generates and saves the JSON report safely.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Creating a safe file string from URL
        safe_url = self.target_url.replace("http://", "").replace("https://", "").replace("/", "_").split(":")[0]
        filename = f"report_{safe_url}_{timestamp}.json"
        filepath = os.path.join(self.reports_dir, filename)
        
        report_data = {
            "metadata": {
                "scan_time": datetime.now().isoformat(),
                "target": self.target_url,
                "engine_version": "1.0.0-demo"
            },
            "executive_summary": {
                "risk_score": self.risk_assessment['score'],
                "risk_level": self.risk_assessment['level'],
                "threat_breakdown": self.risk_assessment['breakdown']
            },
            "advisories": self.recommendations,
            "detailed_logs": self.logs_dump
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=4)
            
        return report_data, filepath
