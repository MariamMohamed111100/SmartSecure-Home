import asyncio
import json
import logging

from fastapi import WebSocket

logger = logging.getLogger("api.websocket")


class WebSocketManager:
    def __init__(self):
        self.connections: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(
        self,
        websocket: WebSocket,
    ):
        await websocket.accept()

        self.connections.add(websocket)

        self.loop = asyncio.get_running_loop()

        logger.info(
            "WebSocket connected. clients=%d",
            len(self.connections),
        )

    def disconnect(
        self,
        websocket: WebSocket,
    ):
        self.connections.discard(websocket)

        logger.info(
            "WebSocket disconnected. clients=%d",
            len(self.connections),
        )

    async def broadcast(
        self,
        message: dict,
    ):
        if not self.connections:
            return

        payload = json.dumps(message)

        disconnected = []

        for websocket in list(
            self.connections
        ):
            try:
                await websocket.send_text(
                    payload
                )

            except Exception:
                disconnected.append(
                    websocket
                )

        for websocket in disconnected:
            self.disconnect(websocket)


manager = WebSocketManager()