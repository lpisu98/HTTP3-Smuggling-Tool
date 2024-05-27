from starlette.requests import Request
from starlette.responses import Response
from urllib.parse import unquote
import asyncio
import aiohttp


class Proxy:
    def __init__(self, base_url, max_concurrency=20):
        self.base_url = base_url
        self.session = None
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def __call__(self, scope, receive, send):
        if self.session is None:
            self.session = aiohttp.ClientSession()

        request = Request(scope, receive)
        method = request.method
        url = self.base_url
        headers = request.headers.mutablecopy()
        del headers["host"]
        headers["connection"] = "keep-alive"
        data = await request.body()
        kwargs = {"method": method, "url": url, "data": data, "headers": headers}
        async with self.semaphore:
            original = await self.session.request(**kwargs)
            body = await original.read()
        response = Response(body, status_code=original.status, headers=original.headers)
        await response(scope, receive, send)

app = Proxy("http://localhost:5000")
