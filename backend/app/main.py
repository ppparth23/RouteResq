"""Main FastAPI application entrypoint for Vulnex AI."""

from contextlib import asynccontextmanager
import http
import logging
import uuid
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import findings, health, remediation, scans, validation
from app.api.v1 import v1_router
from app.config import settings
from app.storage.database import init_db

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("vulnex.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Vulnex AI database...")
    init_db(settings.database_path)
    logger.info("Database schema initialized successfully.")
    yield
    logger.info("Vulnex AI backend shutting down...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="VULNEX AI — Static Security Analysis, AI Explanation, and Verified Code Repair API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)


# Request ID Middleware
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:10]}"
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# CORS Configuration using FRONTEND_ORIGIN and CORS_ORIGINS
cors_origins = settings.get_effective_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Standardized Error Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    request_id = getattr(request.state, "request_id", None)
    status_phrase = http.HTTPStatus(exc.status_code).name if exc.status_code in http.HTTPStatus._value2member_map_ else "HTTP_ERROR"
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": status_phrase,
            "message": str(exc.detail),
            "request_id": request_id
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=422,
        content={
            "error_code": "VALIDATION_ERROR",
            "message": str(exc),
            "request_id": request_id
        }
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None)
    logger.error(f"Unhandled server error [req: {request_id}] {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An internal server error occurred. Please contact the system administrator.",
            "request_id": request_id
        }
    )


# Mount API Routers
# v1 REST API Contract
app.include_router(v1_router)

# Base routes for compatibility
app.include_router(health.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(remediation.router)
app.include_router(validation.router)


@app.get("/", tags=["Root"])
def read_root():
    """Service discovery root endpoint."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "v1_api": "/api/v1",
        "documentation": "/docs",
        "health": "/api/v1/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.vulnex_host, port=settings.vulnex_port, reload=True)
