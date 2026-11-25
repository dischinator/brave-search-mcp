# brave-search-mcp

MCP-Server (Streamable HTTP oder stdio) im Docker-Container, der eine Websuche über die **Brave Search API** als Tool bereitstellt.

| Tool | Parameter |
|---|---|
| `web_search` | `query`, `num_results` (1–20), `page` (1–10), `language`, `country`, `site`, `freshness` (`day`, `week`, `month`, `year`), `safe_search` (`off`, `moderate`, `strict`) |
| `brave_quota` | `calibrate_spent_usd` (Ausgaben laut Dashboard übernehmen), `refresh_rate_limits` (bool, kostet 1 Anfrage) |

Jeder Treffer enthält `title`, `url`, `domain`, `snippet` und `age` (Alter der Seite, falls bekannt). Hat Brave die Anfrage korrigiert, steht die korrigierte Fassung in `corrected_query`.

Jede Suche wird im Container-Log protokolliert (Anfrage, Parameter, Trefferzahl, Dauer, Fehler):

```bash
docker compose logs -f brave-search-mcp
```

`brave_quota` schätzt das verbleibende Guthaben des laufenden Monats, denn Brave hat keinen Guthaben-Endpunkt. Der Server zählt jede erfolgreiche Anfrage, rechnet sie mit `BRAVE_COST_PER_REQUEST` ab und vergleicht mit `BRAVE_MONTHLY_BUDGET`. Der Zähler liegt im Docker-Volume `usage-data` (`/data/usage.json`), übersteht also Neustarts, und beginnt zum UTC-Monatswechsel bei 0.

Suchen mit demselben API-Key außerhalb dieses Servers zählt er nicht mit. Weicht die Schätzung vom [Brave-API-Dashboard](https://api-dashboard.search.brave.com) ab, das Tool einmal mit `calibrate_spent_usd` und dem Dashboard-Wert aufrufen (z.B. `0.10`).

## Start

API-Key unter https://brave.com/search/api/ anlegen, dann:

```bash
cp env.example .env   # BRAVE_API_KEY eintragen, optional MCP_AUTH_TOKEN setzen
docker compose up -d --build
curl http://localhost:8000/health
```

MCP-Endpunkt: `http://localhost:8000/mcp`. Der Port ist in `docker-compose.yml` nur an `127.0.0.1` gebunden. Für den Zugriff aus dem Netz die Bindung ändern **und** `MCP_AUTH_TOKEN` setzen, am besten mit TLS-Reverse-Proxy davor.

## Client-Anbindung

Claude Code:

```bash
claude mcp add --transport http brave-search http://localhost:8000/mcp
```

Mit Token zusätzlich `--header "Authorization: Bearer <MCP_AUTH_TOKEN>"` anhängen.

Claude Desktop (`claude_desktop_config.json`, über `mcp-remote`):

```json
"brave-search": {
  "command": "npx",
  "args": ["mcp-remote", "http://localhost:8000/mcp"]
}
```

Mit Token: `"--header", "Authorization:${AUTH_HEADER}"` an `args` anhängen und `"env": {"AUTH_HEADER": "Bearer <MCP_AUTH_TOKEN>"}` ergänzen.

## Konfiguration

| Variable | Default | |
|---|---|---|
| `BRAVE_API_KEY` | – | erforderlich |
| `DEFAULT_LANGUAGE` / `DEFAULT_COUNTRY` | `de` / `de` | Standardwerte, wenn das Tool keine übergibt |
| `MIN_INTERVAL_SECONDS` | `1.1` | Mindestabstand zwischen zwei Suchen (Free-Plan: 1 Anfrage/Sekunde) |
| `BRAVE_COST_PER_REQUEST` | `0.005` | Preis pro Anfrage in USD für die Guthaben-Schätzung |
| `BRAVE_MONTHLY_BUDGET` | `5.00` | Monatsbudget in USD (Free-Credits bzw. Spend-Limit) |
| `USAGE_FILE` | `/data/usage.json` | Ablage des Verbrauchszählers |
| `HTTP_TIMEOUT` | `15` | Sekunden pro API-Anfrage |
| `MCP_TRANSPORT` | `http` | `http` oder `stdio` |
| `MCP_PORT` | `8000` | |
| `MCP_AUTH_TOKEN` | leer | Bearer-Token; leer = keine Authentifizierung (`/health` bleibt immer offen) |
| `LOG_LEVEL` | `INFO` | |
