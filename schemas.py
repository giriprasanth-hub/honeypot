from pydantic import BaseModel, Field, model_validator
from typing import List, Optional, Dict, Any

# --- INPUT SCHEMA (OMNIVOROUS) ---
class MessageInput(BaseModel):
    message: Optional[str] = ""
    sender_id: Optional[str] = "unknown"

    @model_validator(mode='before')
    @classmethod
    def unify_input(cls, data: Any) -> Any:
        # Handle case where data is already a string
        if isinstance(data, str):
            return {"message": data}
        
        # Handle case where data is a list (take first string)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str) and len(item) > 0:
                    return {"message": item}
            return {"message": ""}
        
        # Handle dictionary case
        if isinstance(data, dict):
            # First, check ALL string values (not just >5 chars)
            found_text = None
            for key in ['message', 'text', 'content', 'input', 'prompt', 'query', 'msg', 'body', 'payload']:
                if key in data and isinstance(data[key], str) and data[key].strip():
                    found_text = data[key]
                    break
            
            # If still not found, look for ANY string value
            if not found_text:
                for key, value in data.items():
                    if isinstance(value, str) and value.strip():
                        found_text = value
                        break
            
            # Assign to message field
            if found_text:
                data['message'] = found_text.strip()
            else:
                data['message'] = ""
        
        # Ensure sender_id exists
        if isinstance(data, dict) and 'sender_id' not in data:
            data['sender_id'] = "unknown"
            
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