"""
Session API - Query and manage the current Chambers session.
"""

from typing import Any

from fastapi import APIRouter, HTTPException

from gcs.models import SessionInfo

router = APIRouter(prefix="/api/session", tags=["session"])

# Module-level state store for the current session
_session_state: dict[str, Any] = {}


def set_session(info: dict[str, Any]) -> None:
    """Update the current session state (used internally by other modules)."""
    global _session_state
    _session_state = info


def clear_session() -> None:
    """Clear the current session state."""
    global _session_state
    _session_state = {}


@router.get("/current", response_model=SessionInfo)
async def get_current_session():
    """Return information about the current active session, or 404 if none."""
    if not _session_state:
        raise HTTPException(
            status_code=404,
            detail="No active session",
        )

    try:
        return SessionInfo(**_session_state)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Session state is malformed: {e}",
        )
