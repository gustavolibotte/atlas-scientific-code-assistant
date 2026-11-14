"""Loopback streamable-HTTP MCP server for tests: uvicorn on 127.0.0.1:0 in a thread.

A bearer gate answers 401 (optionally advertising ``resource_metadata``) unless the
request carries ``Authorization: Bearer <token>``. ``redirect_to`` answers every request
with a 307 to another origin instead. Only booleans about the Authorization header are
recorded, never its value. Everything is synthetic and loopback only.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import uvicorn
from fake_mcp_server import FakeState, build_server

Scope = dict[str, Any]


@dataclass(frozen=True)
class SeenRequest:
    method: str
    path: str
    authorized: bool
    had_authorization: bool


class LoopbackMcpServer:
    """``with LoopbackMcpServer(token=...) as server: server.url``."""

    def __init__(
        self,
        mode: str = "normal",
        *,
        token: str,
        advertise_resource_metadata: bool = False,
        redirect_to: str | None = None,
        plain: bool = False,
    ) -> None:
        self.token = token
        self.state = FakeState()
        self.requests: list[SeenRequest] = []
        self._advertise = advertise_resource_metadata
        self._redirect_to = redirect_to
        self._inner = (
            None
            if plain
            else build_server(mode, state=self.state, token=token).streamable_http_app()
        )
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(("127.0.0.1", 0))
        self.port: int = self._socket.getsockname()[1]
        config = uvicorn.Config(
            self._app,
            log_level="critical",
            lifespan="off" if plain else "on",
            access_log=False,
            timeout_graceful_shutdown=1,
            interface="asgi3",
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [self._socket]}, daemon=True
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    async def _send_plain(self, send: Any, status: int, headers: list[tuple[bytes, bytes]]) -> None:
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b""})

    async def _app(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            if self._inner is not None:
                await self._inner(scope, receive, send)
            return
        headers = dict(scope["headers"])
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        authorized = authorization == f"Bearer {self.token}"
        self.requests.append(
            SeenRequest(scope["method"], scope["path"], authorized, bool(authorization))
        )
        if self._redirect_to is not None:
            await self._send_plain(send, 307, [(b"location", self._redirect_to.encode())])
            return
        if self._inner is None:
            await self._send_plain(send, 404, [])
            return
        if not authorized:
            challenge = b'Bearer realm="asca-test"'
            if self._advertise:
                challenge += b', resource_metadata="http://127.0.0.1/.well-known/x"'
            await self._send_plain(send, 401, [(b"www-authenticate", challenge)])
            return
        await self._inner(scope, receive, send)

    def __enter__(self) -> LoopbackMcpServer:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline or not self._thread.is_alive():
                raise RuntimeError("loopback MCP server did not start")
            time.sleep(0.01)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
        self._socket.close()
