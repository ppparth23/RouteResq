"""Health check endpoint for Vulnex API v1."""

from typing import Any, Dict
from fastapi import APIRouter
from app.config import settings
from app.services.ai_service import AIService

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=Dict[str, Any])
async def get_health_v1():
    """
    Returns system status, service name, version, and AI provider status.
    Distinguishes whether the AI provider is merely configured vs tested and available,
    without exposing any secrets.
    """
    ai_status = await AIService.check_provider_status()

    return {
        "status": "ok",
        "service": "vulnex-api",
        "version": settings.app_version,
        "ai_provider": ai_status
    }
