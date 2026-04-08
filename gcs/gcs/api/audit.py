"""
Audit API - Query and verify the Chambers audit log.
"""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from gcs.models import AuditEntry

router = APIRouter(prefix="/api/audit", tags=["audit"])

# Default audit log path (can be overridden via environment)
AUDIT_LOG_PATH = Path("/data/audit.ndjson")


@router.get("/entries", response_model=list[AuditEntry])
async def get_audit_entries(since: int = Query(default=0, ge=0)):
    """
    Return audit entries from the NDJSON audit log.

    Args:
        since: Return entries with sequence number >= this value.
    """
    if not AUDIT_LOG_PATH.exists():
        return []

    entries: list[AuditEntry] = []

    try:
        with open(AUDIT_LOG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entry = AuditEntry(**data)
                    if entry.sequence >= since:
                        entries.append(entry)
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read audit log: {e}",
        )

    return entries


@router.get("/verify")
async def verify_audit():
    """Verify the integrity of the audit log. (Stub - not implemented yet.)"""
    return {
        "status": "not implemented yet",
        "message": "Use the chambers-verify CLI tool or make verify for full verification.",
    }
