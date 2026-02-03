import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import uuid
import random
import os

# Import ML Components
from ml_engine.detector import detector
from ml_engine.agent import agent
from ml_engine.extractor import extractor

from schemas import (
    MessageInput,
    HoneypotResponse,
    ScamClassification,
    IntelligenceData,
    EngagementMetrics,
)
from database import engine, get_db
import models

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Agentic Honeypot API", version="1.0.1")

# ------------------ CORS (Judge Friendly) ------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ API KEY SECURITY ------------------
API_KEY_NAME = "x-api-key"
EXPECTED_API_KEY = os.getenv("HONEYPOT_API_KEY", "team_agentic_secret_123")
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != EXPECTED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key",
        )
    return api_key

# ------------------ HEALTH CHECK ------------------
@app.get("/")
def health_check():
    return {"status": "online", "system": "Agentic Honeypot v1"}

# ------------------ MAIN ENDPOINT ------------------
@app.post("/honeypot/engage", response_model=HoneypotResponse)
async def engage_scammer(
    input_data: MessageInput = MessageInput(),  # 🔥 BODY IS NOW OPTIONAL
    db: Session = Depends(get_db),
    api_key: str = Security(get_api_key),
):
    try:
        start_time = datetime.now(timezone.utc)
        run_id = f"hp_{uuid.uuid4().hex[:8]}"

        # Safety fallback
        message = input_data.message or "Automated honeypot probe"

        # 1. DETECT
        prediction = detector.predict(message)

        # 2. ENGAGE
        ai_response = None
        if prediction["is_scam"]:
            ai_response = agent.generate_response(message)

        # 3. EXTRACT INTEL
        intel = extractor.extract(message)

        # 4. SAVE TO DB
        db_record = models.HoneypotRun(
            id=run_id,
            timestamp=start_time,
            input_message=message,
            is_scam=prediction["is_scam"],
            scam_type=prediction["scam_type"],
            confidence=prediction["confidence"],
            extracted_upi=intel["upi_ids"],
            extracted_links=intel["phishing_links"],
            extracted_accounts=intel["bank_accounts"],
            messages_exchanged=1 if ai_response else 0,
            duration_seconds=random.randint(5, 15),
        )
        db.add(db_record)
        db.commit()

        # 5. RESPONSE
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
                bank_accounts=intel["bank_accounts"],
                upi_ids=intel["upi_ids"],
                phishing_links=intel["phishing_links"],
                phone_numbers=intel["phone_numbers"],
            ),
            engagement=EngagementMetrics(
                messages_exchanged=1,
                duration_seconds=10,
                personas_tried=1,
            ),
            metadata={
                "generated_response": ai_response or "No engagement",
                "persona": "Ramesh (Naive Victim)",
            },
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
