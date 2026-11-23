"""MCP-Server für die Websuche über die Brave Search API.

Benötigt BRAVE_API_KEY (https://brave.com/search/api/).
Transport (Env MCP_TRANSPORT): "http" (Streamable HTTP unter /mcp, Default) oder "stdio".
"""

from __future__ import annotations

import asyncio
import hmac
import html
import logging
import os
import re
import time
from typing import Annotated, Any, Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import Field

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("web-search-mcp")
logging.getLogger("httpx").setLevel(logging.WARNING)  # sonst landet der API-Aufruf zusätzlich im Log


class _IgnoreClosedSSE(logging.Filter):
    """Unterdrückt harmloses Rauschen: Der Client schließt den GET-/mcp-SSE-Stream (Reconnect),
    das MCP-SDK loggt dann 'Error in standalone SSE writer' mit anyio.ClosedResourceError."""

    def filter(self, record: logging.LogRecord) -> bool:
        if "standalone SSE writer" in record.getMessage() and record.exc_info:
            return record.exc_info[0].__name__ != "ClosedResourceError"
        return True


logging.getLogger("mcp.server.streamable_http").addFilter(_IgnoreClosedSSE())

BRAVE_API_KEY = os.getenv("BRAVE_API_KEY", "")
BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
DEFAULT_LANG = os.getenv("DEFAULT_LANGUAGE", "de")
DEFAULT_COUNTRY = os.getenv("DEFAULT_COUNTRY", "de")
MIN_INTERVAL = float(os.getenv("MIN_INTERVAL_SECONDS", "1.1"))  # Free-Plan: 1 Anfrage/Sekunde
TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "15"))
AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")
HOST = os.getenv("MCP_HOST", "0.0.0.0")
PORT = int(os.getenv("MCP_PORT", "8000"))

FRESHNESS = {"day": "pd", "week": "pw", "month": "pm", "year": "py"}
TAG_RE = re.compile(r"<[^>]+>")


class SearchError(Exception):
    pass


class BraveClient:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._client: httpx.AsyncClient | None = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=TIMEOUT, headers={
                "Accept": "application/json",
                "X-Subscription-Token": BRAVE_API_KEY,
            })
        return self._client

    async def search(self, params: dict[str, Any]) -> dict[str, Any]:
        if not BRAVE_API_KEY:
            raise SearchError("BRAVE_API_KEY ist nicht gesetzt.")
        async with self._lock:  # Anfragen nacheinander mit Mindestabstand (Rate-Limit)
            wait = MIN_INTERVAL - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                r = await self._http().get(BRAVE_URL, params=params)
            except httpx.HTTPError as e:
                raise SearchError(f"Netzwerkfehler: {e}") from e
            finally:
                self._last = time.monotonic()

        if r.status_code == 429:
            raise SearchError("Rate-Limit der Brave API erreicht. Bitte kurz warten oder Monatskontingent prüfen.")
        if r.status_code in (401, 403):
            raise SearchError("Brave API lehnt den API-Key ab (BRAVE_API_KEY prüfen).")
        if r.status_code != 200:
            try:
                detail = r.json().get("error", {}).get("detail") or r.text
            except ValueError:
                detail = r.text
            raise SearchError(f"Brave API Fehler {r.status_code}: {str(detail)[:300]}")
        if remaining := r.headers.get("x-ratelimit-remaining"):
            log.debug("Brave-Kontingent übrig: %s", remaining)
        return r.json()


brave = BraveClient()

mcp = FastMCP(
    "web-search",
    instructions="Websuche über die Brave Search API. Nutze web_search für aktuelle Informationen aus dem Web.",
    host=HOST,
    port=PORT,
)


def _clean(text: str | None) -> str | None:
    return html.unescape(TAG_RE.sub("", text)).strip() if text else None


@mcp.tool()
async def web_search(
    query: Annotated[str, Field(min_length=1, max_length=400, description="Suchanfrage, unterstützt Operatoren wie \"exakte Phrase\", -ausschluss, site:, filetype:")],
    num_results: Annotated[int, Field(ge=1, le=20, description="Anzahl Ergebnisse (1-20)")] = 10,
    page: Annotated[int, Field(ge=1, le=10, description="Ergebnisseite für Paging (1-10)")] = 1,
    language: Annotated[str | None, Field(description="Sprachcode der Ergebnisse, z.B. 'de' oder 'en'")] = None,
    country: Annotated[str | None, Field(description="Ländercode, z.B. 'de', 'us'")] = None,
    site: Annotated[str | None, Field(description="Suche auf eine Domain beschränken, z.B. 'heise.de'")] = None,
    freshness: Annotated[Literal["day", "week", "month", "year"] | None, Field(description="Nur Ergebnisse aus dem letzten Tag/Woche/Monat/Jahr")] = None,
    safe_search: Annotated[Literal["off", "moderate", "strict"], Field(description="Filter für nicht jugendfreie Inhalte")] = "moderate",
) -> dict[str, Any]:
    """Durchsucht das Web und liefert Titel, URL, Snippet und Alter der Treffer."""
    q = f"site:{site} {query}" if site else query
    lang = language or DEFAULT_LANG
    ctry = (country or DEFAULT_COUNTRY).upper()
    params: dict[str, Any] = {
        "q": q,
        "count": num_results,
        "offset": page - 1,
        "country": ctry,
        "search_lang": lang,
        "safesearch": safe_search,
        "text_decorations": "false",
    }
    if freshness:
        params["freshness"] = FRESHNESS[freshness]

    log.info("Suche: %r (seite=%d lang=%s country=%s safe=%s zeitraum=%s)",
             q, page, lang, ctry, safe_search, freshness or "-")
    t0 = time.monotonic()
    try:
        data = await brave.search(params)
    except SearchError as e:
        log.warning("Suche fehlgeschlagen: %r nach %.1fs: %s", q, time.monotonic() - t0, e)
        raise

    results = [
        {
            "title": _clean(it.get("title")),
            "url": it.get("url"),
            "domain": (it.get("meta_url") or {}).get("hostname"),
            "snippet": _clean(it.get("description")),
            "age": it.get("age"),
        }
        for it in (data.get("web") or {}).get("results", [])[:num_results]
    ]
    log.info("Suche fertig: %r, %d Treffer in %.1fs", q, len(results), time.monotonic() - t0)

    out: dict[str, Any] = {"query": q, "page": page, "results": results}
    altered = (data.get("query") or {}).get("altered")
    if altered:
        out["corrected_query"] = altered
    return out


class BearerAuthMiddleware:
    """Einfache Bearer-Token-Prüfung (nur aktiv, wenn MCP_AUTH_TOKEN gesetzt ist). /health bleibt offen."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope.get("path") != "/health":
            auth = dict(scope.get("headers", [])).get(b"authorization", b"")
            if not hmac.compare_digest(auth, self.expected):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
                return
        await self.app(scope, receive, send)


def build_http_app() -> Any:
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    app = mcp.streamable_http_app()

    async def health(_request: Any) -> JSONResponse:
        return JSONResponse({"status": "ok", "api_key": bool(BRAVE_API_KEY)})

    app.router.routes.append(Route("/health", health))
    return BearerAuthMiddleware(app, AUTH_TOKEN) if AUTH_TOKEN else app


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "http").lower()
    log.info("Starte web-search-mcp (transport=%s)", transport)
    if not BRAVE_API_KEY:
        log.warning("BRAVE_API_KEY nicht gesetzt – Suchen werden fehlschlagen.")
    if transport == "stdio":
        mcp.run(transport="stdio")
        return
    if not AUTH_TOKEN:
        log.warning("MCP_AUTH_TOKEN nicht gesetzt – der HTTP-Endpunkt ist ohne Authentifizierung erreichbar.")
    import uvicorn
    uvicorn.run(build_http_app(), host=HOST, port=PORT, log_level=LOG_LEVEL.lower())


if __name__ == "__main__":
    main()
