from sqlalchemy import Column, String, Boolean, Float, Integer, JSON, DateTime
from database import Base
import datetime

class HoneypotRun(Base):
    __tablename__ = "honeypot_runs"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    input_message = Column(String)
    
    # Classification
    is_scam = Column(Boolean)
    scam_type = Column(String)
    confidence = Column(Float)
    
    # Intelligence
    extracted_upi = Column(JSON)
    extracted_links = Column(JSON)
    extracted_accounts = Column(JSON)
    
    # Engagement
    messages_exchanged = Column(Integer)
    duration_seconds = Column(Integer)
    