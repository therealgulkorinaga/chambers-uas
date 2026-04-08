"""
Pydantic models for the Chambers GCS API.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---- Manifest-related models ----


class NetworkFlow(BaseModel):
    """A declared network flow in the manifest."""
    protocol: str
    src: str
    dst: str
    port: int
    description: str = ""


class DenyRule(BaseModel):
    """A deny rule specifying forbidden actions."""
    action: str
    target: str
    description: str = ""


class PreserveRule(BaseModel):
    """A rule specifying what data to preserve and for how long."""
    data_type: str
    retention_days: int = 90
    description: str = ""


class StakeholderDecl(BaseModel):
    """A stakeholder declaration in the manifest."""
    name: str
    role: str
    contact: str = ""
    notify_on: list[str] = Field(default_factory=list)


class ManifestMeta(BaseModel):
    """Top-level manifest metadata."""
    version: str = "1.0"
    drone_id: str = ""
    operator: str = ""
    mission_type: str = ""
    stakeholders: list[StakeholderDecl] = Field(default_factory=list)
    preserve: list[PreserveRule] = Field(default_factory=list)
    deny: list[DenyRule] = Field(default_factory=list)
    network_flows: list[NetworkFlow] = Field(default_factory=list)


# ---- Session models ----


class SessionInfo(BaseModel):
    """Information about the current Chambers session."""
    session_id: str
    state: str
    public_key_hex: str
    manifest_hash_hex: str
    start_time: datetime


# ---- Audit models ----


class AuditEntry(BaseModel):
    """A single entry from the audit log."""
    sequence: int
    timestamp: datetime
    entry_type: str
    signature_hex: str


class SealedEventInfo(BaseModel):
    """Information about a sealed event."""
    id: str
    event_type: str
    trigger_timestamp: datetime
    preservation_window_start: datetime
    preservation_window_end: datetime
    stakeholders: list[str] = Field(default_factory=list)
    retention_days: int = 90


class AnomalyInfo(BaseModel):
    """Information about a detected anomaly."""
    id: str
    timestamp: datetime
    pattern: str
    severity: str
    process_name: str = ""
    process_id: Optional[int] = None


class VerifyResult(BaseModel):
    """Result of verifying an audit log."""
    total_entries: int
    signatures_valid: bool
    hash_chain_intact: bool
    first_invalid: Optional[int] = None
    sealed_events_count: int = 0
    anomalies_count: int = 0
