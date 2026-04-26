class AdvisoryEngine:
    """
    Translates technical threat flags into actionable, developer-friendly remediations.
    """
    def __init__(self, classified_logs, risk_assessment):
        self.classified_logs = classified_logs
        self.risk_assessment = risk_assessment
        
        self.kb = {
            "SQL_INJECTION_PATTERN": "Implement Prepared Statements (Parameterized Queries). Use an ORM for database interactions.",
            "XSS_PATTERN": "Sanitize and validate all user inputs. Implement Content Security Policy (CSP) headers.",
            "LOCAL_FILE_INCLUSION": "Avoid passing user input directly to filesystem APIs. Use indirect object references mapping.",
            "SENSITIVE_FILE_ACCESS": "Restrict access to configuration and backup files. Ensure proper directory permissions and .htaccess blocks.",
            "ABNORMAL_CHARACTER_DENSITY": "Implement strict input validation and WAF (Web Application Firewall) rules."
        }

    def generate_recommendations(self):
        recommendations = set()
        
        for log in self.classified_logs:
            for flag in log.get('detected_flags', []):
                if flag in self.kb:
                    recommendations.add(f"{flag.replace('_', ' ')}: {self.kb[flag]}")
                    
        if not recommendations and self.risk_assessment['score'] > 0:
            recommendations.add("General: Review web server access logs for anomalous behavior periodically.")
        elif not recommendations:
            recommendations.add("Excellent hygiene: Continue monitoring and maintain current WAF postures.")
            
        return list(recommendations)
