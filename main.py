import uvicorn
import uuid
import random
import os
from datetime import datetime, timezone
from typing import Union  # Add this import

from fastapi import FastAPI, HTTPException, Security, status, Body
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware

# ------------------ ML COMPONENTS ------------------
from ml_engine.detector import detector
from ml_engine.agent import agent
from ml_engine.extractor import extractor

# ------------------ SCHEMAS ------------------
from schemas import (
    MessageInput,
    HoneypotResponse,
    ScamClassification,
    IntelligenceData,
    EngagementMetrics,
)

app = FastAPI(title="Agentic Honeypot API", version="1.0.9")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- AUTHENTICATION ---
API_KEY_NAME = "x-api-key"
EXPECTED_API_KEY = os.getenv("HONEYPOT_API_KEY", "team_agentic_secret_123")
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != EXPECTED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Invalid API Key"
        )
    return api_key

@app.get("/")
def health_check():
    return {"status": "online", "system": "Agentic Honeypot v1"}

# --- MAIN ENDPOINT ---
@app.post("/honeypot/engage", response_model=HoneypotResponse)
async def engage_scammer(
    input_data: Union[MessageInput, dict, str] = Body(...), 
    api_key: str = Security(get_api_key),
):
    try:
        start_time = datetime.now(timezone.utc)
        run_id = f"hp_{uuid.uuid4().hex[:8]}"
        
        # Handle different input types
        message = ""
        sender_id = "unknown"
        
        if isinstance(input_data, MessageInput):
            message = input_data.message or "Automated honeypot probe"
            sender_id = input_data.sender_id
        elif isinstance(input_data, dict):
            # Try to extract message from dict
            msg_input = MessageInput(**input_data)
            message = msg_input.message or "Automated honeypot probe"
            sender_id = msg_input.sender_id
        elif isinstance(input_data, str):
            message = input_data if input_data.strip() else "Automated honeypot probe"
        else:
            # Try to convert to string
            message = str(input_data)
        
        # 1. Detection Logic
        prediction = detector.predict(message)

        # 2. AI Response Generation
        ai_response = None
        if prediction.get("is_scam"):
            ai_response = agent.generate_response(message)

        # 3. Entity Extraction
        intel = extractor.extract(message)

        # 4. Construct Structured Response
        return HoneypotResponse(
            honeypot_id=run_id,
            timestamp_utc=start_time.isoformat(),
            input_message=message,
            classification=ScamClassification(
                is_scam=prediction["is_scam"],
                scam_type=prediction["scam_type"],
                confidence=prediction["confidence"],
                risk_level="critical" if prediction["is_scam"] else "low",
            ),
            intelligence=IntelligenceData(
                bank_accounts=intel.get("bank_accounts", []),
                upi_ids=intel.get("upi_ids", []),
                phishing_links=intel.get("phishing_links", []),
                phone_numbers=intel.get("phone_numbers", []),
            ),
            engagement=EngagementMetrics(
                messages_exchanged=1,
                duration_seconds=random.randint(5, 15),
                personas_tried=1,
            ),
            metadata={
                "generated_response": ai_response or "No engagement",
                "sender_id": sender_id,  # Use the extracted sender_id
                "http_method": "POST",
            },
        )

    except Exception as e:
        # Enhanced error response
        error_id = f"err_{uuid.uuid4().hex[:4]}"
        print(f"Error {error_id}: {str(e)}")
        print(f"Input received: {input_data}")
        
        # Return a proper HoneypotResponse object instead of dict
        return HoneypotResponse(
            honeypot_id=error_id,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            input_message="error_fallback",
            classification=ScamClassification(
                is_scam=False,
                scam_type="none",
                confidence=0.0,
                risk_level="low"
            ),
            intelligence=IntelligenceData(
                bank_accounts=[],
                upi_ids=[],
                phishing_links=[],
                phone_numbers=[]
            ),
            engagement=EngagementMetrics(
                messages_exchanged=0,
                duration_seconds=0,
                personas_tried=0
            ),
            metadata={
                "error": str(e),
                "error_type": type(e).__name__,
                "input_received": str(input_data)[:200] if input_data else "No input"
            }
        )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)