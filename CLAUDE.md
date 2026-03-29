# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server (picks a free port automatically, writes to .port)
python app.py

# Run on a specific port
PORT=8001 python app.py

# Run with uvicorn directly (dev mode with auto-reload)
uvicorn app:app --reload --port 8000
```

No build step — the frontend is a single static `index.html` file served directly by Starlette.
No test suite exists in this project.

## Architecture

### Overview
IP Roller — allocates static/floating IPs in **VK Cloud** (OpenStack) or **Yandex Cloud** (VPC) and retries until finding one whose address falls within a CIDR whitelist (`cidrwhitelist.txt`, ~30 000 Russian mobile subnets). Multiple accounts (from both providers) can be searched in parallel within the same session.

### Backend (`app.py`) — Starlette + asyncio + SSE

**Startup**: `cidrwhitelist.txt` is parsed into `WHITELIST: list[ipaddress.IPv4Network]` at module load.

**Session model**: `SESSIONS: dict[str, dict]` is the in-process store. Each session (UUID key) holds:
- `tasks` — list of running `asyncio.Task` objects (one per account)
- `events` — deque of buffered SSE event dicts (capped at 50 000)
- `queues` — list of `asyncio.Queue` objects for live delivery to SSE consumers

**VK Cloud rolling loop** (`run_rolling_loop`):
1. Authenticate via OpenStack Keystone (`get_scoped_token`) → scoped token + expiry
2. Discover external network via Neutron API (`get_external_network_id`)
3. Loop: allocate FloatingIP → `ip_in_whitelist` → if miss, delete + random delay → retry
4. Proactive token refresh when < 2–10 min remain; 3 retries on 404/500 with 30 s/60 s backoff
5. 429 → exponential backoff (reads `Retry-After`, caps at 120 s)
6. Anti-fraud: configurable staggered start delay, periodic mandatory rests

**Yandex Cloud rolling loop** (`run_yc_rolling_loop`):
1. Build PS256 JWT from `authorized_key.json` (`_make_yc_jwt`, salt_length=32 per RFC 7518) → exchange for IAM token (`get_yc_iam_token`)
2. Round-robin zone selection from user-chosen subset of `ru-central1-{a,b,d,e}`
3. Loop: `allocate_yc_address` → poll async Operation until done → `ip_in_whitelist` → if miss, `delete_yc_address` + delay → retry
4. IAM token refresh (TTL 12 h by default, proactive at < 10 min); 3 retries on failure
5. Same anti-fraud parameters as VK loop

**`ip_in_whitelist(ip_str, whitelist=None)`**: uses the session-level custom whitelist if provided, otherwise falls back to global `WHITELIST`.

**Key API routes**:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Serve `index.html` |
| `/api/start` | POST | Create session, launch asyncio tasks |
| `/api/stream` | GET | SSE: replay buffered events, then stream live |
| `/api/stop` | POST | Cancel tasks for one session |
| `/api/stop-all` | POST | Cancel all sessions |
| `/api/sessions` | GET | List active sessions (for reconnect detection) |
| `/api/ips` | GET | List FloatingIPs for one VK account |
| `/api/yc-ips` | POST | List static IPs for one YC account (requires key JSON) |
| `/api/check-ip` | GET | Check arbitrary IP against whitelist |
| `/api/check-proxy` | GET | Verify proxy via ipify.org |
| `/api/whitelist-info` | GET | Return default whitelist CIDR count + filename |

### Frontend (`index.html`) — single-file SPA, no framework

**State**:
- `accounts[]` — VK Cloud accounts; `ycAccounts[]` — Yandex Cloud accounts
- `currentTab` — active provider tab (`'vk'` | `'yc'`)
- `customWhitelist` — parsed CIDR list from uploaded file, or `null` for default

All state is persisted to `localStorage` (including YC key fields, zone selections).

**Auth flows**:
- **VK**: OpenRC v3 file parsed client-side; only individual field values are sent to server
- **YC**: `authorized_key.json` parsed client-side (`parseAuthorizedKey`); full key JSON sent to `/api/start` per account

**Whitelist card**: radio toggles between "standard" (server-side `cidrwhitelist.txt`) and "custom" (file upload). Uploaded file is parsed client-side into CIDR lines, count is shown. `getActiveWhitelist()` returns the array (or `null`) which is passed as `custom_whitelist` in `POST /api/start`.

**Real-time updates**: one `EventSource` per session consumes `/api/stream`. Backend replays all buffered events before streaming live ones. Each account gets its own scrollable log panel; hit events show the IP and zone (YC).

### Data Flow
```
Browser POST /api/start  {accounts: [...], yc_accounts: [...], custom_whitelist: [...] | null}
  → app.py creates SESSIONS[id], spawns asyncio Tasks (_acc_worker dispatches by type)
  → each Task runs run_rolling_loop() or run_yc_rolling_loop() yielding SSE event dicts
  → events buffered in SESSIONS[id]["events"] + pushed to live queues

Browser GET /api/stream?session_id=...
  → replays buffered events, then awaits live queue
  → browser EventSource updates log panels in real time
```

### Credentials & Secrets
- OpenRC v3: parsed client-side, never stored server-side
- YC `authorized_key.json`: contains RSA-2048 private key; excluded by `.gitignore`
- API tokens: passed per-request; not persisted server-side
- `.gitignore` excludes: `mcs*-openrc.sh`, `*.token`, `.port`, `authorized_key.json`, `*authorized_key*.json`
