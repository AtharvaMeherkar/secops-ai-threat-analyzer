class RiskEngine:
    """
    Aggregates threat intelligence and calculates overarching security posture scores.
    """
    def __init__(self, classified_logs):
        self.classified_logs = classified_logs

    def calculate_risk(self):
        """
        Aggregates logs and assigns an overall risk score (0-100) and risk level.
        """
        base_score = 0
        weights = {
            "High Risk": 30,
            "Suspicious": 10,
            "Normal": 0
        }
        
        counts = {"High Risk": 0, "Suspicious": 0, "Normal": 0}
        
        for log in self.classified_logs:
            level = log.get('classification', 'Normal')
            counts[level] += 1
            base_score += weights.get(level, 0)
        
        # Cap the score at 100
        final_score = min(base_score, 100)
        
        if final_score >= 70:
            risk_level = "CRITICAL"
        elif final_score >= 30:
            risk_level = "HIGH"
        elif final_score >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        return {
            "score": final_score,
            "level": risk_level,
            "breakdown": counts
        }
