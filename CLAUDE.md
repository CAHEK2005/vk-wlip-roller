# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server (picks a free port automatically)
python app.py

# Run with uvicorn directly (dev mode with auto-reload)
uvicorn app:app --reload --port 8000
```

No build step — the frontend is a single static `index.html` file served directly by Starlette.
No test suite exists in this project.

## Architecture

### Overview
VK Cloud Whitelist IP Roller — allocates Floating IPs in VK Cloud (OpenStack) and keeps retrying until finding one whose address falls within a CIDR whitelist (`cidrwhitelist.txt`, ~30 000 Russian mobile subnets). Supports multiple accounts searched in parallel.

### Backend (`app.py`) — Starlette + asyncio + SSE

**Startup**: `cidrwhitelist.txt` is parsed into a list of `ipaddress.IPv4Network` objects at module load time.

**Session model**: `SESSIONS: dict[str, dict]` is the in-process store. Each session (UUID key) holds:
- `tasks` — list of running `asyncio.Task` objects (one per account)
- `events` — deque of buffered SSE event dicts (capped at 50 000)
- `queues` — list of `asyncio.Queue` objects for live delivery to SSE consumers

**Rolling loop** (`run_rolling_loop` async generator):
1. Authenticate via OpenStack Keystone (`get_scoped_token`) to get a scoped token
2. Discover the external network via Neutron API (`get_external_network_id`)
3. Loop: allocate a Floating IP → check `ip_in_whitelist` → if miss, delete and wait (random delay + occasional long pause) → retry
4. On match: yield a success event and stop
5. Proactive token refresh when < 2–10 min remain before expiry
6. 429 responses trigger exponential backoff (reads `Retry-After`, caps at 120 s)

**Anti-detection built-ins**: 8 rotating User-Agent strings mimicking OpenStack clients; configurable random delays; random long pauses (configurable chance/duration per account).

**Key API routes**:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Serve `index.html` |
| `/api/start` | POST | Create session, launch asyncio tasks |
| `/api/stream` | GET | SSE: replay buffered events, then stream live |
| `/api/stop` | POST | Cancel tasks for one session |
| `/api/stop-all` | POST | Cancel all sessions |
| `/api/sessions` | GET | List active sessions (for reconnect detection) |
| `/api/ips` | GET | List Floating IPs for one account |
| `/api/check-ip` | GET | Check arbitrary IP against whitelist |
| `/api/check-proxy` | GET | Verify proxy via ipify.org |

### Frontend (`index.html`) — single-file SPA, no framework

**State**: `accounts[]` array holds per-account config (auth URL, project ID, region, token, proxy, IPs). Persisted to `localStorage`.

**OpenRC parsing**: done entirely client-side in the browser; credentials are never sent to the server as a file — only individual field values are posted.

**Real-time updates**: one `EventSource` per session consumes `/api/stream`. On reconnect the backend replays all buffered events before streaming live ones. Each account gets its own scrollable log panel with color-coded rows (miss = red, hit = green).

**Timer**: browser-side countdown; fires `POST /api/stop` when it expires.

### Data Flow
```
Browser POST /api/start
  → app.py creates SESSIONS[id], spawns asyncio Tasks
  → each Task runs run_rolling_loop() yielding SSE event dicts
  → events buffered in SESSIONS[id]["events"] + pushed to live queues

Browser GET /api/stream?session_id=...
  → replays buffered events, then awaits live queue
  → browser EventSource updates log panels in real time
```

### Credentials & Secrets
- OpenRC v3 file: parsed client-side (never stored on server)
- API token: passed per-request; not persisted server-side
- `.gitignore` excludes `mcs*-openrc.sh`, `*.token`, `.port`
- Proxy strings (SOCKS5/HTTP) are per-account and passed at session start
