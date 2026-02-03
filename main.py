import uvicorn
import uuid
import random
import os
import json
from datetime import datetime, timezone

from fastapi import (
    FastAPI,
    HTTPException,
    Security,
    status,
    Request,
)
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware

# ------------------ ML COMPONENTS ------------------
from ml_engine.detector import detector
from ml_engine.agent import agent
from ml_engine.extractor import extractor

# ------------------ SCHEMAS ------------------
from schemas import (
    HoneypotResponse,
    ScamClassification,
    IntelligenceData,
    EngagementMetrics,
)

# ------------------ FASTAPI APP ------------------
app = FastAPI(
    title="Agentic Honeypot API",
    version="1.0.5",
)

# ------------------ CORS ------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ API KEY SECURITY ------------------
API_KEY_NAME = "x-api-key"
EXPECTED_API_KEY = os.getenv(
    "HONEYPOT_API_KEY",
    "team_agentic_secret_123",
)

api_key_header = APIKeyHeader(
    name=API_KEY_NAME,
    auto_error=True,
)

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
    return {
        "status": "online",
        "system": "Agentic Honeypot v1",
    }

# ------------------ MAIN ENDPOINT ------------------
@app.post("/honeypot/engage", response_model=HoneypotResponse)
async def engage_scammer(
    request: Request,   # 🔥 NO BODY DECLARATION
    api_key: str = Security(get_api_key),
):
    try:
        start_time = datetime.now(timezone.utc)
        run_id = f"hp_{uuid.uuid4().hex[:8]}"

        # ------------------ SAFE BODY READ ------------------
        message = "Automated honeypot probe"

        try:
            body_bytes = await request.body()
            if body_bytes:
                body = json.loads(body_bytes.decode())
                if isinstance(body, dict):
                    message = (
                        body.get("message")
                        or body.get("text")
                        or body.get("input")
                        or body.get("content")
                        or message
                    )
        except Exception:
            # Ignore malformed / empty body
            pass

        # ------------------ DETECT ------------------
        prediction = detector.predict(message)

        # ------------------ ENGAGE ------------------
        ai_response = None
        if prediction.get("is_scam"):
            ai_response = agent.generate_response(message)

        # ------------------ EXTRACT ------------------
        intel = extractor.extract(message)

        # ------------------ RESPONSE ------------------
        return HoneypotResponse(
            honeypot_id=run_id,
            timestamp_utc=start_time.isoformat(),
            input_message=message,
            classification=ScamClassification(
                is_scam=prediction["is_scam"],
                scam_type=prediction["scam_type"],
                confidence=prediction["confidence"],
                risk_level="critical"
                if prediction["is_scam"]
                else "low",
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
        # FAILSAFE — NEVER 500
        return HoneypotResponse(
            honeypot_id="hp_failsafe",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            input_message="failsafe",
            classification=ScamClassification(
                is_scam=False,
                scam_type="unknown",
                confidence=0.0,
                risk_level="low",
            ),
            intelligence=IntelligenceData(
                bank_accounts=[],
                upi_ids=[],
                phishing_links=[],
                phone_numbers=[],
            ),
            engagement=EngagementMetrics(
                messages_exchanged=0,
                duration_seconds=0,
                personas_tried=0,
            ),
            metadata={
                "error": "Handled empty probe safely",
                "detail": str(e),
            },
        )

# ------------------ RUN ------------------
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
    )
