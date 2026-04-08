"""
WebSocket API - Real-time event streaming to connected GCS clients.
"""

import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])

# Set of active WebSocket connections
_active_connections: set[WebSocket] = set()


async def broadcast(message: dict[str, Any]) -> None:
    """Send a JSON message to all connected WebSocket clients."""
    payload = json.dumps(message)
    disconnected: list[WebSocket] = []
    for ws in _active_connections:
        try:
            await ws.send_text(payload)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        _active_connections.discard(ws)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time GCS updates.

    Clients connect here to receive live audit events, session state
    changes, anomaly alerts, and sealed event notifications.
    """
    await websocket.accept()
    _active_connections.add(websocket)

    try:
        # Send a welcome message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to Chambers GCS WebSocket",
        })

        # Keep the connection alive, receiving any client messages
        while True:
            data = await websocket.receive_text()
            # Echo back acknowledgment (clients may send pings or commands)
            try:
                parsed = json.loads(data)
                await websocket.send_json({
                    "type": "ack",
                    "received": parsed,
                })
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON",
                })
    except WebSocketDisconnect:
        pass
    finally:
        _active_connections.discard(websocket)
