from pydantic import BaseModel, Field, model_validator
from typing import List, Optional, Dict, Any

# --- INPUT SCHEMA (FLEXIBLE) ---
class MessageInput(BaseModel):
    # We define multiple optional fields to catch whatever the Judge sends
    message: Optional[str] = None
    text: Optional[str] = None
    content: Optional[str] = None
    input: Optional[str] = None
    
    sender_id: Optional[str] = "unknown"

    # This magic function runs BEFORE validation to normalize the input
    @model_validator(mode='before')
    @classmethod
    def unify_input(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Try to find the message in common field names
            found_text = (
                data.get('message') or 
                data.get('text') or 
                data.get('content') or 
                data.get('input')
            )
            # Force it into the 'message' field so the rest of our code works
            if found_text:
                data['message'] = found_text
        return data

# --- OUTPUT SCHEMAS ---
class ScamClassification(BaseModel):
    is_scam: bool
    scam_type: str
    confidence: float
    risk_level: str

class IntelligenceData(BaseModel):
    bank_accounts: List[str] = Field(default_factory=list)
    upi_ids: List[str] = Field(default_factory=list)
    phishing_links: List[str] = Field(default_factory=list)
    phone_numbers: List[str] = Field(default_factory=list)

class EngagementMetrics(BaseModel):
    messages_exchanged: int
    duration_seconds: int
    personas_tried: int

class HoneypotResponse(BaseModel):
    honeypot_id: str
    timestamp_utc: str
    input_message: Optional[str] = "No content"
    classification: ScamClassification
    intelligence: IntelligenceData
    engagement: EngagementMetrics
    metadata: Dict[str, Any] = Field(default_factory=dict)