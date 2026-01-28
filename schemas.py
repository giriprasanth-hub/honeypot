from pydantic import BaseModel, Field
from typing import List, Optional, Dict

# --- INPUT SCHEMA ---
# This is what the Frontend or WhatsApp wrapper sends to us
class MessageInput(BaseModel):
    message: str = Field(..., example="Your ICICI account is locked. Click here to verify.")
    sender_id: Optional[str] = "unknown"

# --- OUTPUT SCHEMAS (The Intelligence Layer) ---

class ScamClassification(BaseModel):
    is_scam: bool
    scam_type: str = Field(..., example="upi_phishing")
    confidence: float
    risk_level: str  # critical, high, medium, low

class IntelligenceData(BaseModel):
    bank_accounts: List[Dict[str, float]] = Field(default_factory=list, description="Account numbers with confidence scores")
    upi_ids: List[str] = Field(default_factory=list, description="Extracted UPI IDs")
    phishing_links: List[str] = Field(default_factory=list, description="Malicious URLs found")
    phone_numbers: List[str] = Field(default_factory=list)

class EngagementMetrics(BaseModel):
    messages_exchanged: int
    duration_seconds: int
    personas_tried: int

class HoneypotResponse(BaseModel):
    honeypot_id: str
    timestamp_utc: str
    input_message: str
    classification: ScamClassification
    intelligence: IntelligenceData
    engagement: EngagementMetrics
    metadata: Dict[str, str] = {}