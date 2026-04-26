from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(500), nullable=False)

class ScanReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    report_data = db.Column(db.Text, nullable=False) # JSON blob
    
    def get_report_dict(self):
        return json.loads(self.report_data)
