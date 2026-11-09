from fastapi import APIRouter, HTTPException

from core import progress

router = APIRouter(prefix="/api")


@router.get("/investigate/{investigation_id}/progress")
def investigation_progress(investigation_id: str):
    snapshot = progress.snapshot(investigation_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="No progress is recorded for this investigation.")
    return {"success": True, "data": snapshot}