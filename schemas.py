from pydantic import BaseModel, Field, model_validator
from typing import List, Optional, Dict, Any

# --- INPUT SCHEMA (Fixed to handle Strings & JSON) ---
class MessageInput(BaseModel):
    message: Optional[str] = ""
    sender_id: Optional[str] = "unknown"

    @model_validator(mode='before')
    @classmethod
    def unify_input(cls, data: Any) -> Any:
        # CASE 1: Input is just a raw string (e.g. plain text body)
        if isinstance(data, str):
            return {"message": data}
            
        # CASE 2: Input is a dictionary (JSON)
        if isinstance(data, dict):
            # 1. Try specific common keys first
            found_text = (
                data.get('message') or 
                data.get('text') or 
                data.get('content') or 
                data.get('input') or 
                data.get('prompt') or 
                data.get('query') or 
                data.get('msg') or 
                data.get('body')
            )
            
            # 2. If not found, grab the FIRST string value we see in the dictionary
            if not found_text:
                for key, value in data.items():
                    if isinstance(value, str) and len(value) > 1: 
                        found_text = value
                        break
            
            # 3. Assign it to 'message'
            if found_text:
                data['message'] = str(found_text)
            else:
                data['message'] = "" 
                
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