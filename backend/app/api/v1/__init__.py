"""V1 API Router bundle for Vulnex AI."""

from fastapi import APIRouter
from app.api.v1 import findings, firmware, health, remediations, scans, validations

v1_router = APIRouter(prefix="/api/v1")

v1_router.include_router(health.router)
v1_router.include_router(scans.router)
v1_router.include_router(findings.router)
v1_router.include_router(remediations.router)
v1_router.include_router(validations.router)
v1_router.include_router(firmware.router)

__all__ = ["v1_router"]
