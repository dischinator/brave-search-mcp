# brave-search-mcp

MCP-Server (Streamable HTTP oder stdio) im Docker-Container, der eine Websuche über die **Brave Search API** als Tool bereitstellt.

| Tool | Parameter |
|---|---|
| `web_search` | `query`, `num_results` (1–20), `page` (1–10), `language`, `country`, `site`, `freshness` (`day`, `week`, `month`, `year`), `safe_search` (`off`, `moderate`, `strict`) |

Jeder Treffer enthält `title`, `url`, `domain`, `snippet` und `age` (Alter der Seite, falls bekannt). Hat Brave die Anfrage korrigiert, steht die korrigierte Fassung in `corrected_query`.

Jede Suche wird im Container-Log protokolliert (Anfrage, Parameter, Trefferzahl, Dauer, Fehler):

```bash
docker compose logs -f brave-search-mcp
```

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
| `HTTP_TIMEOUT` | `15` | Sekunden pro API-Anfrage |
| `MCP_TRANSPORT` | `http` | `http` oder `stdio` |
| `MCP_PORT` | `8000` | |
| `MCP_AUTH_TOKEN` | leer | Bearer-Token; leer = keine Authentifizierung (`/health` bleibt immer offen) |
| `LOG_LEVEL` | `INFO` | |
