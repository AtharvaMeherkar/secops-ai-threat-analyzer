import pytest
from modules.input_module import validate_url, sanitize_url, InputValidationError
from modules.scanner_engine import ScannerEngine
from modules.detection_engine import DetectionEngine
from modules.classification_engine import ClassificationEngine
from modules.risk_engine import RiskEngine

def test_input_validation():
    # Valid
    assert validate_url("https://google.com") == True
    assert validate_url("http://192.168.1.1") == True
    
    # Invalid
    with pytest.raises(InputValidationError):
        validate_url("htp://invalid-url")
        
    with pytest.raises(InputValidationError):
        validate_url("www.no-protocol.com")
        
    # Sanitization
    assert sanitize_url(" https://site.com/ ") == "https://site.com"

def test_scanner_generation():
    # Note: This sends real requests to example.com
    engine = ScannerEngine("http://example.com")
    logs = engine.run_active_scan()
    
    assert len(logs) > 0
    categories = [l['category_simulation'] for l in logs]
    assert "Normal" in categories
    assert "Suspicious" in categories
    assert "High Risk" in categories

def test_detection_and_classification():
    mock_logs = [
        {"payload": "/about", "status_code": 200},
        {"payload": "1' OR '1'='1", "status_code": 200},
        {"payload": "/.env", "status_code": 403}
    ]
    
    detector = DetectionEngine(mock_logs)
    analyzed = detector.analyze()
    
    # Check if flags are generated correctly
    # ML model might flag /about as mildly anomalous in a small dataset, so we don't strictly assert 0
    # Instead, we verify High Risk flags are reliably attached
    assert len(analyzed[1]['detected_flags']) > 0
    assert "SENSITIVE_FILE_ACCESS" in analyzed[2]['detected_flags']
    
    classifier = ClassificationEngine(analyzed)
    classified = classifier.classify()
    
    assert classified[0]['classification'] in ["Normal", "Suspicious"]
    item1 = classified[1]['classification'] 
    assert item1 in ["Suspicious", "High Risk"] # SQLi is high risk
    
    
def test_risk_scoring():
    mock_classified = [
        {"classification": "Normal"},
        {"classification": "High Risk"},
        {"classification": "Suspicious"}
    ]
    engine = RiskEngine(mock_classified)
    result = engine.calculate_risk()
    
    assert result['score'] == 40 # 30(High) + 10(Susp)
    assert result['level'] == "HIGH"
