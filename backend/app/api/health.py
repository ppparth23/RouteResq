"""Health check endpoint."""

from datetime import datetime, timezone
import sqlite3
from fastapi import APIRouter
from app.config import settings

router = APIRouter(prefix="/api/health", tags=["Health"])


@router.get("")
def get_health():
    """Returns system status, version, and component health."""
    db_ok = False
    try:
        conn = sqlite3.connect(settings.database_path, timeout=2.0)
        conn.execute("SELECT 1")
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "status": "healthy" if db_ok else "degraded",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.vulnex_env,
        "database": "connected" if db_ok else "unavailable",
        "ai_engine": "gemini" if settings.gemini_api_key else "deterministic_fallback",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
