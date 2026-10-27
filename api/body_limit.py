"""Enforce upload body bounds even without Content-Length (chunked clients)."""
from starlette.exceptions import HTTPException


class UploadBodyLimit:
    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != "/api/analyze/upload":
            return await self.app(scope, receive, send)
        size = 0
        async def bounded_receive():
            nonlocal size
            event = await receive()
            if event["type"] == "http.request":
                size += len(event.get("body", b""))
                if size > self.limit:
                    raise HTTPException(413, "Upload exceeds request size limit")
            return event
        return await self.app(scope, bounded_receive, send)
