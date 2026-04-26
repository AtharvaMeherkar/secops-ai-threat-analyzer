import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer

class MLEngine:
    """
    True ML implementation using Scikit-Learn's Isolation Forest algorithm.
    It builds a vectorized density model of normal web paths to detect zero-day structures.
    """
    def __init__(self):
        # We use a TF-IDF vectorizer to map character n-grams to numerical matrices
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 3))
        # Contamination is the theoretical proportion of anomalies in our dataset
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self._train_baseline_model()

    def _train_baseline_model(self):
        baseline_payloads = [
            "/", "/home", "/about", "/contact", "/dashboard", "/api/v1/health",
            "/products", "/favicon.ico", "/images/logo.png", "/login", "/register",
            "/reset-password?email=test@test.com", "/search?q=shoes",
            # Anchoring extreme outliers
            "/' OR '1'='1", "/../../etc/passwd", "<script>alert(1)</script>"
        ]
        
        # Pad 'normal' traffic to establish a dense cluster boundary for the isolation tree
        extended_baseline = baseline_payloads + ["/api/user/profile"] * 50 + ["/static/css/style.css"] * 50
        
        X_train = self.vectorizer.fit_transform(extended_baseline)
        self.model.fit(X_train)

    def predict_anomaly(self, payload):
        """
        Returns boolean is_anomaly, and numerical float score (-1 to 1).
        Negative scores are severe anomalies.
        """
        if not payload:
            return False, 1.0 # Normal
            
        X_test = self.vectorizer.transform([payload])
        prediction = self.model.predict(X_test)[0]
        score = self.model.decision_function(X_test)[0]
        
        is_anomaly = (prediction == -1)
        return is_anomaly, float(score)
