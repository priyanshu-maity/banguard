import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from api.database import get_investigation, get_report, initialize_database, save_investigation
from api.models import InvestigationRequest
from api.serializer import to_jsonable
from core.orchestrator import run_investigation
from engines.threat_intelligence.verification import verify_report


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("banguard.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    logger.info("BanGuard API database initialized.")
    yield


app = FastAPI(
    title="BanGuard API",
    description="AI-powered web threat detection and digital trust intelligence.",
    version="1.0.0",
    lifespan=lifespan,
)


allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "BANGUARD_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.get("/api/health")
def health_check():
    try:
        initialize_database()
        return {"status": "ok", "service": "banguard-api", "database": "connected"}
    except Exception:
        logger.exception("Health check failed.")
        raise HTTPException(status_code=503, detail="API database is unavailable.")


@app.post("/api/investigate")
def investigate(request: InvestigationRequest):
    try:
        investigation = run_investigation(
            url=request.url,
            investigation_type=request.investigation_type,
            message=request.message,
            submit_to_blockchain=request.submit_to_blockchain,
        )

        result = to_jsonable(investigation)
        save_investigation(result)

        return {
            "success": True,
            "data": result,
        }

    except Exception:
        logger.exception("Investigation request failed.")
        raise HTTPException(
            status_code=500,
            detail="The investigation could not be completed. Check the backend logs.",
        )


@app.get("/api/investigations/{investigation_id}")
def retrieve_investigation(investigation_id: str):
    result = get_investigation(investigation_id)

    if result is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    return {"success": True, "data": result}


@app.get("/api/reports/{report_id}")
def retrieve_report(report_id: str):
    report = get_report(report_id)

    if report is None:
        raise HTTPException(status_code=404, detail="Threat report not found.")

    return {"success": True, "data": report}

@app.get("/api/reports/{report_id}/verify")
def verify_threat_report(report_id: str, version: int | None = None):
    try:
        result = verify_report(report_id, version)

        return {
            "success": True,
            "data": result,
        }

    except Exception:
        logger.exception("Report verification failed.")
        raise HTTPException(
            status_code=500,
            detail="Report verification could not be completed.",
        )
