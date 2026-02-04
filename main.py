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
    version="1.0.8",
    redirect_slashes=False,   # 🔥 CRITICAL FIX
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
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

# ------------------ HEALTH CHECK ------------------
@app.get("/")
def health_check():
    return {"status": "online", "system": "Agentic Honeypot v1"}

# ------------------ CORE HANDLER ------------------
async def honeypot_handler(request: Request):
    start_time = datetime.now(timezone.utc)
    run_id = f"hp_{uuid.uuid4().hex[:8]}"

    message = "Automated honeypot probe"

    try:
        body_bytes = await request.body()
        if body_bytes:
            try:
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
                message = body_bytes.decode(errors="ignore").strip() or message
    except Exception:
        pass

    prediction = detector.predict(message)

    ai_response = None
    if prediction.get("is_scam"):
        ai_response = agent.generate_response(message)

    intel = extractor.extract(message)

    response = HoneypotResponse(
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
            "http_method": request.method,
        },
    )

    return response.model_dump()

# ------------------ BOTH ROUTES (NO REDIRECT) ------------------
@app.api_route("/honeypot/engage", methods=["GET", "POST"])
async def engage_no_slash(
    request: Request,
    api_key: str = Security(get_api_key),
):
    return await honeypot_handler(request)

@app.api_route("/honeypot/engage/", methods=["GET", "POST"])
async def engage_with_slash(
    request: Request,
    api_key: str = Security(get_api_key),
):
    return await honeypot_handler(request)

# ------------------ RUN ------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
