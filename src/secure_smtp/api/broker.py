"""
WebSocket Real-Time Event Broker.

Manages active client WebSocket connections and broadcasts forensic events
such as packet analyses, simulated sessions, and database resets.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts real-time forensic events."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept incoming connection and register in active pool."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove disconnected client from active pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected. Active: %d", len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a JSON message to all active clients, pruning dead connections."""
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


_connection_manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """Get the singleton ConnectionManager instance."""
    return _connection_manager
