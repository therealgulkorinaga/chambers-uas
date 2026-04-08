"""
Manifest API - Load and inspect Chambers manifests.
"""

from typing import Any

import tomllib
from fastapi import APIRouter, HTTPException, UploadFile

router = APIRouter(prefix="/api/manifest", tags=["manifest"])

# Module-level state for the currently loaded manifest
_current_manifest: dict[str, Any] | None = None


@router.post("/load")
async def load_manifest(file: UploadFile):
    """
    Load a TOML manifest file.

    Accepts a file upload, parses it as TOML, performs basic structure
    validation, and stores it as the current manifest.
    """
    global _current_manifest

    if not file.filename or not file.filename.endswith(".toml"):
        raise HTTPException(
            status_code=400,
            detail="Manifest file must have a .toml extension",
        )

    content = await file.read()

    try:
        parsed = tomllib.loads(content.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse TOML: {e}",
        )

    # Basic structure validation
    if "manifest" not in parsed and "chambers" not in parsed:
        raise HTTPException(
            status_code=400,
            detail="Manifest must contain a [manifest] or [chambers] section",
        )

    _current_manifest = parsed

    return {
        "status": "loaded",
        "filename": file.filename,
        "manifest": parsed,
    }


@router.get("/current")
async def get_current_manifest():
    """Return the currently loaded manifest, or 404 if none is loaded."""
    if _current_manifest is None:
        raise HTTPException(
            status_code=404,
            detail="No manifest currently loaded",
        )
    return _current_manifest
