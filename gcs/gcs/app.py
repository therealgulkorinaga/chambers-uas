"""
Chambers GCS - FastAPI application entry point.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from gcs.api import audit, manifest, session, websocket


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Chambers GCS starting...")
    yield
    print("Chambers GCS shutting down...")


app = FastAPI(
    title="Chambers GCS",
    description="Ground Control Station for the Chambers UAS integrity framework",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware - allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(manifest.router)
app.include_router(session.router)
app.include_router(audit.router)
app.include_router(websocket.router)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "chambers-gcs"}
