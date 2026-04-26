class ClassificationEngine:
    """
    Labels analyzed logs and attaches severity metadata.
    """
    def __init__(self, analyzed_logs):
        self.analyzed_logs = analyzed_logs

    def classify(self):
        """
        Classifies each log as Normal, Suspicious, or High Risk based on detection flags.
        """
        classified_logs = []
        for log in self.analyzed_logs:
            flags = log.get('detected_flags', [])
            
            if not flags:
                log['classification'] = "Normal"
                log['reason'] = "No anomalies detected."
            else:
                # High risk markers
                risk_factors = ["SQL_INJECTION_PATTERN", "XSS_PATTERN", "LOCAL_FILE_INCLUSION"]
                is_high_risk = any(rf in flags for rf in risk_factors)
                
                status = log.get('status_code', 200)
                
                if is_high_risk and status in [200, 500]:
                    log['classification'] = "High Risk"
                    log['reason'] = f"Critical threat indicator succeeded (Status {status}): {', '.join(flags)}"
                elif is_high_risk and status in [403, 401, 404]:
                    log['classification'] = "Suspicious"
                    log['reason'] = f"Threat indicator blocked or failed (Status {status}): {', '.join(flags)}"
                else:
                    log['classification'] = "Suspicious"
                    log['reason'] = f"Anomalous behavior or enumeration detected (Status {status}): {', '.join(flags)}"
                    
            classified_logs.append(log)
        return classified_logs
