"""Bounded request handling and metadata-only logs for the demo API."""

import logging
from collections import deque
from time import monotonic

from starlette.responses import JSONResponse

MAX_BODY_BYTES = 131_072  # Fits 10k characters even with JSON Unicode escapes.
REQUESTS_PER_MINUTE = 60  # Per-process fallback; production needs a gateway quota.
logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class RequestBoundaryMiddleware:
    def __init__(self, app):
        self.app = app
        self.requests = deque()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = False
        status = 500

        async def secure_send(message):
            nonlocal started, status
            if message["type"] == "http.response.start":
                started = True
                status = message["status"]
                message["headers"] = list(message.get("headers", [])) + [
                    (key.lower().encode(), value.encode()) for key, value in SECURITY_HEADERS.items()
                ]
            await send(message)

        async def reject(code, detail, headers=None):
            await JSONResponse({"detail": detail}, status_code=code, headers=headers)(scope, receive, secure_send)

        try:
            if scope["path"].rstrip("/") == "/analyze" and scope["method"] == "POST":
                now = monotonic()
                while self.requests and self.requests[0] <= now - 60:
                    self.requests.popleft()
                if len(self.requests) >= REQUESTS_PER_MINUTE:
                    return await reject(429, "Request limit exceeded", {"Retry-After": "60"})
                self.requests.append(now)
                # Count actual bytes, including chunked bodies and dishonest Content-Length.
                body = bytearray()
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > MAX_BODY_BYTES:
                        return await reject(413, "Request body exceeds 131072 bytes")
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
                delivered = False

                async def bounded_receive():
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await receive()

                await self.app(scope, bounded_receive, secure_send)
            else:
                await self.app(scope, receive, secure_send)
        except Exception:
            # Exception strings/tracebacks can contain submitted values.
            logger.error("request_failed")
            if not started:
                await reject(500, "Internal server error")
        finally:
            route = scope.get("route")
            logger.info("request_complete route=%s status=%s", getattr(route, "path", "unmatched"), status)
