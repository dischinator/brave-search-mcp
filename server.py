"""MCP-Server für die Websuche über die Brave Search API.

Benötigt BRAVE_API_KEY (https://brave.com/search/api/).
Transport (Env MCP_TRANSPORT): "http" (Streamable HTTP unter /mcp, Default) oder "stdio".
"""

from __future__ import annotations

import asyncio
import hmac
import html
import json
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
COST_PER_REQUEST = float(os.getenv("BRAVE_COST_PER_REQUEST", "0.005"))  # $5 pro 1.000 Anfragen
MONTHLY_BUDGET = float(os.getenv("BRAVE_MONTHLY_BUDGET", "5.00"))  # Free-Credits bzw. Spend-Limit im Dashboard
USAGE_FILE = os.getenv("USAGE_FILE", "/data/usage.json")
LOG_QUOTA_EVERY = int(os.getenv("LOG_QUOTA_EVERY", "10"))  # Guthaben-Stand alle N Anfragen loggen, 0 = aus

FRESHNESS = {"day": "pd", "week": "pw", "month": "pm", "year": "py"}
TAG_RE = re.compile(r"<[^>]+>")


class SearchError(Exception):
    pass


def _parse_quota(headers: httpx.Headers) -> dict[str, Any] | None:
    """Wertet X-RateLimit-Limit/-Remaining/-Reset aus. Brave liefert je Zeitfenster einen Wert,
    kommagetrennt in der Reihenfolge der X-RateLimit-Policy (z.B. '1;w=1, 2000;w=2592000')."""
    split = lambda name: [v.strip() for v in headers.get(name, "").split(",") if v.strip()]
    limits, remaining, resets = (split(f"x-ratelimit-{n}") for n in ("limit", "remaining", "reset"))
    if not remaining:
        return None
    windows = [p.split("w=", 1)[1] if "w=" in p else None for p in split("x-ratelimit-policy")]
    out: list[dict[str, Any]] = []
    for i, rem in enumerate(remaining):
        win = int(windows[i]) if i < len(windows) and windows[i] and windows[i].isdigit() else None
        entry: dict[str, Any] = {
            "window": {1: "second", 2592000: "month"}.get(win, f"{win}s" if win else f"#{i + 1}"),
            "limit": int(limits[i]) if i < len(limits) and limits[i].isdigit() else None,
            "remaining": int(rem) if rem.isdigit() else rem,
        }
        if i < len(resets) and resets[i].isdigit():
            entry["reset_in_seconds"] = int(resets[i])
            entry["reset_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + int(resets[i])))
        if entry["limit"] == 0:  # Guthaben-Tarife: Brave meldet 0 = kein festes Limit in diesem Fenster
            entry.update(limit=None, remaining=None, unlimited=True)
        elif isinstance(entry["limit"], int) and isinstance(entry["remaining"], int):
            entry["used"] = entry["limit"] - entry["remaining"]
        out.append(entry)
    return {"windows": out, "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "_ts": time.time()}


def _month() -> str:
    return time.strftime("%Y-%m", time.gmtime())  # Brave rechnet nach UTC-Kalendermonat ab


class UsageTracker:
    """Zählt erfolgreiche API-Anfragen pro Monat und schätzt daraus die Kosten.
    Persistiert in USAGE_FILE (Docker-Volume), damit Neustarts den Zähler nicht verlieren."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.persistent = True
        self.state = {"month": _month(), "requests": 0, "spent_usd": 0.0}
        try:
            with open(path, encoding="utf-8") as f:
                self.state.update(json.load(f))
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.warning("Verbrauchsdatei %s nicht lesbar (%s), starte bei 0.", path, e)
        self._rollover()

    def _rollover(self) -> None:
        if self.state["month"] != _month():
            self.state = {"month": _month(), "requests": 0, "spent_usd": 0.0}
            self._save()

    def _save(self) -> None:
        if not self.persistent:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.state, f)
            os.replace(tmp, self.path)
        except OSError as e:
            self.persistent = False
            log.warning("Verbrauch kann nicht in %s gespeichert werden (%s), zähle nur im Speicher.", self.path, e)

    def record(self) -> None:
        self._rollover()
        self.state["requests"] += 1
        self.state["spent_usd"] = round(self.state["spent_usd"] + COST_PER_REQUEST, 6)
        self._save()
        if LOG_QUOTA_EVERY > 0 and self.state["requests"] % LOG_QUOTA_EVERY == 0:
            snap = self.snapshot()
            log.info("Brave-Guthaben (Schätzung %s): $%.2f von $%.2f verbraucht (%s%%), noch ca. $%.2f bzw. %s Anfragen, %d Anfragen gezählt",
                     snap["month"], snap["spent_estimate_usd"], snap["budget_usd"], snap["percent_used"],
                     snap["remaining_estimate_usd"], snap["remaining_requests_estimate"], snap["requests_counted"])

    def calibrate(self, spent_usd: float) -> None:
        self._rollover()
        self.state["spent_usd"] = round(spent_usd, 6)
        self._save()

    def snapshot(self) -> dict[str, Any]:
        self._rollover()
        spent = self.state["spent_usd"]
        y, m = map(int, self.state["month"].split("-"))
        return {
            "month": self.state["month"],
            "requests_counted": self.state["requests"],
            "spent_estimate_usd": round(spent, 2),
            "budget_usd": MONTHLY_BUDGET,
            "remaining_estimate_usd": round(max(MONTHLY_BUDGET - spent, 0.0), 2),
            "remaining_requests_estimate": max(int((MONTHLY_BUDGET - spent) / COST_PER_REQUEST + 1e-9), 0) if COST_PER_REQUEST > 0 else None,
            "percent_used": round(spent / MONTHLY_BUDGET * 100, 1) if MONTHLY_BUDGET > 0 else None,
            "cost_per_request_usd": COST_PER_REQUEST,
            "resets_at": f"{y + m // 12:04d}-{m % 12 + 1:02d}-01T00:00:00Z",
            "persistent": self.persistent,
        }


class BraveClient:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._client: httpx.AsyncClient | None = None
        self.quota: dict[str, Any] | None = None  # Kontingent aus den Headern der letzten Antwort

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
        usage.record()
        if quota := _parse_quota(r.headers):
            self.quota = quota
            log.debug("Brave-Kontingent: %s", quota)
        return r.json()


usage = UsageTracker(USAGE_FILE)
brave = BraveClient()

mcp = FastMCP(
    "web-search",
    instructions="Websuche über die Brave Search API. Nutze web_search für aktuelle Informationen aus dem Web, brave_quota für das verbleibende API-Guthaben.",
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


@mcp.tool()
async def brave_quota(
    calibrate_spent_usd: Annotated[float | None, Field(ge=0, description="Bisherige Ausgaben dieses Monats laut Brave-Dashboard ('This month ... spent'), um die Schätzung abzugleichen")] = None,
    refresh_rate_limits: Annotated[bool, Field(description="True holt aktuelle Rate-Limits per Test-Suche (kostet 1 Anfrage)")] = False,
) -> dict[str, Any]:
    """Liefert das geschätzte verbleibende Brave-API-Guthaben dieses Monats.

    Brave bietet keinen Guthaben-Endpunkt. Der Server zählt deshalb seine eigenen erfolgreichen
    Anfragen und rechnet sie mit BRAVE_COST_PER_REQUEST gegen BRAVE_MONTHLY_BUDGET. Anfragen mit
    demselben Key außerhalb dieses Servers fehlen; mit calibrate_spent_usd lässt sich der Stand
    an das Dashboard angleichen.
    """
    if calibrate_spent_usd is not None:
        usage.calibrate(calibrate_spent_usd)
        log.info("Verbrauch auf $%.2f kalibriert", calibrate_spent_usd)
    if refresh_rate_limits:
        log.info("Rate-Limit-Abfrage über Test-Suche")
        await brave.search({"q": "brave", "count": 1, "text_decorations": "false"})
    out = usage.snapshot()
    if brave.quota:
        out["rate_limits"] = brave.quota["windows"]
        out["rate_limits_age_seconds"] = int(time.time() - brave.quota["_ts"])
    out["note"] = ("Schätzung aus den über diesen Server gezählten Anfragen. Verbindlicher Stand im "
                   "Brave-API-Dashboard; abweichende Werte mit calibrate_spent_usd übernehmen.")
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
