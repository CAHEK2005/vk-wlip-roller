#!/usr/bin/env python3
"""
VK Cloud Whitelist IP Roller
Web interface for finding/replacing floating IPs that fall in a CIDR whitelist.

Authentication: OpenStack permanent API token + OpenRC v3 file (auth_url, project_id, region).
Supports multiple accounts with parallel search and per-account proxy (SOCKS5/HTTP).
"""

import asyncio
import ipaddress
import json
import os
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
import uvicorn
from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
WHITELIST_FILE = SCRIPT_DIR / "cidrwhitelist.txt"
INDEX_FILE = SCRIPT_DIR / "index.html"

# ---------------------------------------------------------------------------
# Rate limiting defaults
# ---------------------------------------------------------------------------
RATE_LIMIT_BASE = 30.0
RATE_LIMIT_MAX = 120.0

DEFAULT_DELAY_MIN = 3.0
DEFAULT_DELAY_MAX = 8.0

# ---------------------------------------------------------------------------
# Whitelist — loaded once at startup
# ---------------------------------------------------------------------------
WHITELIST: list[ipaddress.IPv4Network] = []


def _load_whitelist() -> None:
    skipped = 0
    with open(WHITELIST_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                WHITELIST.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                skipped += 1
    print(f"[startup] Whitelist loaded: {len(WHITELIST)} networks"
          + (f" ({skipped} skipped)" if skipped else ""))


_load_whitelist()

# ---------------------------------------------------------------------------
# User-Agent rotation
# ---------------------------------------------------------------------------
_USER_AGENTS = [
    "python-openstackclient/6.3.0 openstacksdk/1.3.0",
    "python-openstackclient/6.2.0 openstacksdk/1.1.0",
    "openstacksdk/1.3.1 keystoneauth1/5.3.0 python-requests/2.31.0 CPython/3.11.6 Linux/5.15.0",
    "openstacksdk/2.0.0 keystoneauth1/5.4.0 python-requests/2.31.0 CPython/3.12.0 Linux/6.1.0",
    "python-neutronclient/9.3.0 keystoneauth1/5.2.0",
    "python-neutronclient/9.2.0 python-requests/2.28.2 CPython/3.10.12 Linux/5.15.0",
    "python-keystoneclient/5.1.0 keystoneauth1/5.3.0",
    "python-keystoneclient/5.2.0 keystoneauth1/5.4.0 python-requests/2.31.0",
]

# ---------------------------------------------------------------------------
# Session model — persistent background execution
# ---------------------------------------------------------------------------

@dataclass
class Session:
    id: str
    events: list[dict] = field(default_factory=list)
    queues: list[asyncio.Queue] = field(default_factory=list)
    tasks: list = field(default_factory=list)
    done: bool = False


SESSIONS: dict[str, Session] = {}
MAX_SESSION_EVENTS = 50_000

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class RateLimitError(Exception):
    def __init__(self, wait: float):
        self.wait = wait
        super().__init__(f"Rate limit — wait {wait:.0f}s")


def ip_in_whitelist(ip_str: str) -> ipaddress.IPv4Network | None:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net in WHITELIST:
        if addr in net:
            return net
    return None


def _make_client(proxy_url: str | None) -> httpx.AsyncClient:
    """Create an httpx AsyncClient with a random OpenStack User-Agent, optionally with a proxy."""
    ua = random.choice(_USER_AGENTS)
    headers = {"User-Agent": ua}
    if proxy_url:
        return httpx.AsyncClient(proxy=proxy_url, headers=headers)
    return httpx.AsyncClient(headers=headers)


def _sse_tagged(account_id: str, event: str, data) -> dict:
    """Build an SSE event dict with account_id tag."""
    if isinstance(data, str):
        payload = {"account_id": account_id, "msg": data}
    else:
        payload = {"account_id": account_id, **data}
    return {"event": event, "data": json.dumps(payload)}


# ---------------------------------------------------------------------------
# OpenStack auth
# ---------------------------------------------------------------------------

async def get_scoped_token(
    client: httpx.AsyncClient,
    auth_url: str,
    project_id: str,
    region: str,
    api_token: str,
) -> tuple[str, str, datetime]:
    """
    Exchange permanent API token for a project-scoped session token.
    Returns (scoped_token, neutron_endpoint_url, expires_at).
    """
    auth_url = auth_url.rstrip("/")
    payload = {
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": {"id": api_token},
            },
            "scope": {
                "project": {"id": project_id},
            },
        }
    }
    resp = await client.post(f"{auth_url}/auth/tokens", json=payload, timeout=30)
    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"Ошибка аутентификации ({resp.status_code}): {resp.text[:500]}"
        )

    scoped_token = resp.headers.get("X-Subject-Token", "")
    if not scoped_token:
        raise RuntimeError("Ответ аутентификации не содержит X-Subject-Token")

    token_body = resp.json().get("token", {})
    catalog = token_body.get("catalog", [])
    expires_str = token_body.get("expires_at", "")
    try:
        expires_at = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    neutron_url = _find_endpoint(catalog, "network", region)
    if not neutron_url:
        available = [e.get("type") for e in catalog]
        raise RuntimeError(
            f"Neutron endpoint не найден в каталоге. Доступные типы: {available}"
        )
    return scoped_token, neutron_url.rstrip("/"), expires_at


def _find_endpoint(catalog: list, svc_type: str, region: str) -> str | None:
    for entry in catalog:
        if entry.get("type") != svc_type:
            continue
        for ep in entry.get("endpoints", []):
            if ep.get("interface") == "public" and ep.get("region_id") == region:
                return ep.get("url", "")
    return None


# ---------------------------------------------------------------------------
# Neutron helpers
# ---------------------------------------------------------------------------

async def get_external_network_id(
    client: httpx.AsyncClient, neutron_url: str, token: str
) -> str:
    resp = await client.get(
        f"{neutron_url}/v2.0/networks",
        params={"router:external": "True"},
        headers={"X-Auth-Token": token},
        timeout=30,
    )
    resp.raise_for_status()
    networks = resp.json().get("networks", [])
    if not networks:
        raise RuntimeError("Внешние сети не найдены в проекте")
    return networks[0]["id"]


async def list_floating_ips(
    client: httpx.AsyncClient, neutron_url: str, token: str
) -> list[dict]:
    resp = await client.get(
        f"{neutron_url}/v2.0/floatingips",
        headers={"X-Auth-Token": token},
        timeout=30,
    )
    resp.raise_for_status()
    fips = resp.json().get("floatingips", [])
    return sorted(fips, key=lambda x: x.get("floating_ip_address", ""))


async def allocate_floating_ip(
    client: httpx.AsyncClient, neutron_url: str, token: str, ext_net_id: str
) -> dict:
    resp = await client.post(
        f"{neutron_url}/v2.0/floatingips",
        json={"floatingip": {"floating_network_id": ext_net_id}},
        headers={"X-Auth-Token": token},
        timeout=30,
    )
    if resp.status_code == 429:
        retry_after = float(resp.headers.get("Retry-After", RATE_LIMIT_BASE))
        raise RateLimitError(retry_after)
    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"Не удалось выделить Floating IP ({resp.status_code}): {resp.text[:300]}"
        )
    return resp.json()["floatingip"]


async def delete_floating_ip(
    client: httpx.AsyncClient, neutron_url: str, token: str, fip_id: str
) -> None:
    resp = await client.delete(
        f"{neutron_url}/v2.0/floatingips/{fip_id}",
        headers={"X-Auth-Token": token},
        timeout=30,
    )
    if resp.status_code == 404:
        print(f"[warn] Floating IP {fip_id} уже удалён (404)")
        return
    if resp.status_code not in (200, 204):
        print(f"[warn] DELETE {fip_id} вернул {resp.status_code}: {resp.text[:200]}")


# ---------------------------------------------------------------------------
# Core rolling loop (single account)
# ---------------------------------------------------------------------------

async def run_rolling_loop(
    creds: dict,
    old_ip_id: str | None,
    delay_min: float,
    delay_max: float,
    proxy_url: str | None,
    account_id: str,
    long_pause_chance: float = 0.0,
    long_pause_min: float = 300.0,
    long_pause_max: float = 1200.0,
):
    """
    Async generator that yields SSE events tagged with account_id.
    Allocates floating IPs until one matches the whitelist.
    If old_ip_id is given, deletes it first (replace mode).
    """
    def ev(event: str, data) -> dict:
        return _sse_tagged(account_id, event, data)

    yield ev("status", f"Аутентификация ({creds['auth_url']})...")

    client = _make_client(proxy_url)
    try:
        try:
            scoped_token, neutron_url, expires_at = await get_scoped_token(
                client, creds["auth_url"], creds["project_id"],
                creds["region"], creds["api_token"],
            )
        except Exception as e:
            yield ev("error", f"Ошибка аутентификации: {e}")
            return

        yield ev("status", f"OK. Neutron: {neutron_url}")
        refresh_at = expires_at - timedelta(seconds=random.uniform(120, 600))

        try:
            ext_net_id = await get_external_network_id(client, neutron_url, scoped_token)
        except Exception as e:
            yield ev("error", f"Ошибка получения внешней сети: {e}")
            return

        yield ev("status", f"Внешняя сеть: {ext_net_id}")

        # Replace mode: delete old IP first to free quota slot
        if old_ip_id:
            yield ev("status", f"Удаляем выбранный IP {old_ip_id}...")
            try:
                await delete_floating_ip(client, neutron_url, scoped_token, old_ip_id)
                old_ip_id = None
                yield ev("status", "Удалён. Начинаем поиск замены...")
            except Exception as e:
                yield ev("error", f"Не удалось удалить выбранный IP: {e}")
                return

        attempt = 0
        prev_fip: dict | None = None
        rate_limit_wait = RATE_LIMIT_BASE

        try:
            while True:
                # Proactive token refresh
                if datetime.now(timezone.utc) >= refresh_at:
                    yield ev("status", "Обновление токена и смена UA...")
                    await client.aclose()
                    client = _make_client(proxy_url)
                    try:
                        scoped_token, neutron_url, expires_at = await get_scoped_token(
                            client, creds["auth_url"], creds["project_id"],
                            creds["region"], creds["api_token"],
                        )
                        refresh_at = expires_at - timedelta(seconds=random.uniform(120, 600))
                        yield ev("status", "Токен обновлён.")
                    except Exception as e:
                        yield ev("error", f"Ошибка обновления токена: {e}")
                        return

                attempt += 1

                # Delete previous non-matching IP before allocating new one
                if prev_fip:
                    yield ev("status",
                             f"Удаляем {prev_fip['floating_ip_address']}...")
                    await delete_floating_ip(
                        client, neutron_url, scoped_token, prev_fip["id"]
                    )
                    prev_fip = None
                    delay = random.uniform(delay_min, delay_max)
                    yield ev("status", f"Пауза {delay:.1f}с...")
                    await asyncio.sleep(delay)

                yield ev("status", f"Попытка {attempt}...")

                # Allocate with rate-limit retry
                while True:
                    try:
                        fip = await allocate_floating_ip(
                            client, neutron_url, scoped_token, ext_net_id
                        )
                        rate_limit_wait = RATE_LIMIT_BASE
                        break
                    except RateLimitError as e:
                        yield ev("status",
                                 f"Лимит запросов API (429) — пауза {e.wait:.0f}с...")
                        await asyncio.sleep(e.wait)
                        rate_limit_wait = min(rate_limit_wait * 2, RATE_LIMIT_MAX)
                    except Exception as e:
                        yield ev("error", f"Ошибка выделения IP: {e}")
                        return

                ip_str = fip["floating_ip_address"]
                matched_net = ip_in_whitelist(ip_str)

                yield ev("attempt", {
                    "n": attempt,
                    "ip": ip_str,
                    "id": fip["id"],
                    "match": str(matched_net) if matched_net else None,
                })

                if matched_net:
                    yield ev("success", {
                        "ip": ip_str,
                        "id": fip["id"],
                        "network": str(matched_net),
                        "attempts": attempt,
                    })
                    return
                else:
                    prev_fip = fip
                    # Random long pause (independent per account)
                    if long_pause_chance > 0 and random.random() < long_pause_chance:
                        lp = random.uniform(long_pause_min, long_pause_max)
                        yield ev("status",
                                 f"Длинная пауза {lp/60:.1f} мин. (антиблок)...")
                        await asyncio.sleep(lp)

        except asyncio.CancelledError:
            if prev_fip:
                try:
                    await delete_floating_ip(
                        client, neutron_url, scoped_token, prev_fip["id"]
                    )
                except Exception:
                    pass
            raise

        except Exception as e:
            if prev_fip:
                try:
                    await delete_floating_ip(
                        client, neutron_url, scoped_token, prev_fip["id"]
                    )
                except Exception:
                    pass
            yield ev("error", f"Ошибка: {e}")

    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

async def homepage(request: Request) -> HTMLResponse:
    html = INDEX_FILE.read_text(encoding="utf-8")
    return HTMLResponse(html)


async def api_check_proxy(request: Request) -> JSONResponse:
    """Verify that requests actually go through the given proxy."""
    proxy_url = request.query_params.get("proxy_url", "").strip()
    if not proxy_url:
        return JSONResponse({"error": "Укажите параметр ?proxy_url="}, status_code=400)

    try:
        async with _make_client(proxy_url) as client:
            resp = await client.get("https://api.ipify.org?format=json", timeout=15)
            resp.raise_for_status()
            seen_ip = resp.json().get("ip", "")
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})

    return JSONResponse({"ok": True, "ip": seen_ip})


async def api_check_ip(request: Request) -> JSONResponse:
    ip = request.query_params.get("ip", "").strip()
    if not ip:
        return JSONResponse({"error": "Укажите параметр ?ip="}, status_code=400)
    matched = ip_in_whitelist(ip)
    return JSONResponse({
        "ip": ip,
        "in_whitelist": matched is not None,
        "network": str(matched) if matched else None,
    })


async def api_ips(request: Request) -> JSONResponse:
    """Return list of floating IPs and external network ID for one account."""
    p = request.query_params
    creds = {
        "auth_url":   p.get("auth_url", "").strip(),
        "project_id": p.get("project_id", "").strip(),
        "region":     p.get("region", "RegionOne").strip(),
        "api_token":  p.get("api_token", "").strip(),
    }
    proxy_url = p.get("proxy_url", "").strip() or None
    missing = [k for k, v in creds.items() if not v]
    if missing:
        return JSONResponse(
            {"error": f"Не заполнены поля: {', '.join(missing)}"}, status_code=400
        )

    try:
        async with _make_client(proxy_url) as client:
            scoped_token, neutron_url, _ = await get_scoped_token(
                client, creds["auth_url"], creds["project_id"],
                creds["region"], creds["api_token"],
            )
            fips = await list_floating_ips(client, neutron_url, scoped_token)
            ext_net_id = await get_external_network_id(client, neutron_url, scoped_token)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    return JSONResponse({
        "ips": [
            {
                "id": f["id"],
                "ip": f.get("floating_ip_address", ""),
                "status": f.get("status", ""),
                "fixed_ip": f.get("fixed_ip_address") or "",
            }
            for f in fips
        ],
        "ext_net_id": ext_net_id,
    })


async def api_start(request: Request) -> JSONResponse:
    """Create a persistent session and start the rolling loop(s) in background."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Неверный JSON в теле запроса"}, status_code=400)

    accounts = body.get("accounts", [])
    delay_min = float(body.get("delay_min", DEFAULT_DELAY_MIN))
    delay_max = float(body.get("delay_max", DEFAULT_DELAY_MAX))
    long_pause_chance = float(body.get("long_pause_chance", 0.0)) / 100.0
    long_pause_min = float(body.get("long_pause_min", 5)) * 60.0
    long_pause_max = float(body.get("long_pause_max", 20)) * 60.0

    if not accounts:
        return JSONResponse({"error": "Не передано ни одного аккаунта"}, status_code=400)

    required = ("auth_url", "project_id", "region", "api_token")
    for acc in accounts:
        missing = [k for k in required if not (acc.get(k) or "").strip()]
        if missing:
            name = acc.get("name", acc.get("id", "?"))
            return JSONResponse(
                {"error": f"Аккаунт '{name}': не заполнены поля {missing}"},
                status_code=400,
            )

    if delay_min > delay_max:
        delay_min, delay_max = delay_max, delay_min
    if long_pause_min > long_pause_max:
        long_pause_min, long_pause_max = long_pause_max, long_pause_min

    session_id = str(uuid.uuid4())
    session = Session(id=session_id)
    SESSIONS[session_id] = session

    remaining = [len(accounts)]

    def _push(event: dict) -> None:
        if len(session.events) < MAX_SESSION_EVENTS:
            session.events.append(event)
        for q in list(session.queues):
            q.put_nowait(event)

    def _account_done() -> None:
        remaining[0] -= 1
        if remaining[0] <= 0:
            session.done = True
            for q in list(session.queues):
                q.put_nowait(None)

    async def _acc_worker(acc: dict) -> None:
        try:
            async for event in run_rolling_loop(
                creds=acc,
                old_ip_id=acc.get("old_ip_id") or None,
                delay_min=delay_min,
                delay_max=delay_max,
                proxy_url=acc.get("proxy_url") or None,
                account_id=acc["id"],
                long_pause_chance=long_pause_chance,
                long_pause_min=long_pause_min,
                long_pause_max=long_pause_max,
            ):
                _push(event)
        except asyncio.CancelledError:
            pass
        finally:
            _account_done()

    for acc in accounts:
        task = asyncio.create_task(_acc_worker(acc))
        session.tasks.append(task)

    return JSONResponse({"session_id": session_id})


async def api_stream(request: Request):
    """SSE stream for a session — replays buffered events then streams live."""
    session_id = request.query_params.get("session_id", "").strip()
    session = SESSIONS.get(session_id)

    if not session:
        async def _not_found():
            yield {
                "event": "error",
                "data": json.dumps({"account_id": "system", "msg": "Сессия не найдена"}),
            }
        return EventSourceResponse(_not_found())

    async def _stream():
        # Subscribe to queue BEFORE taking snapshot to avoid missing events
        q: asyncio.Queue = asyncio.Queue()
        session.queues.append(q)
        try:
            # Replay all buffered events
            for event in list(session.events):
                yield event
            if session.done:
                return
            # Stream live events
            while True:
                item = await q.get()
                if item is None:
                    break
                yield item
        finally:
            if q in session.queues:
                session.queues.remove(q)

    return EventSourceResponse(_stream())


async def api_stop(request: Request) -> JSONResponse:
    """Cancel all tasks for a session."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Неверный JSON"}, status_code=400)

    session_id = body.get("session_id", "").strip()
    session = SESSIONS.pop(session_id, None)
    if session:
        for task in session.tasks:
            task.cancel()
    return JSONResponse({"ok": True})


async def api_sessions(request: Request) -> JSONResponse:
    """List active sessions (used by frontend for reconnect check)."""
    active = [
        {"session_id": s.id, "done": s.done, "events": len(s.events)}
        for s in SESSIONS.values()
    ]
    return JSONResponse({"sessions": active})


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

routes = [
    Route("/", homepage),
    Route("/api/check-proxy", api_check_proxy),
    Route("/api/check-ip", api_check_ip),
    Route("/api/ips", api_ips),
    Route("/api/start", api_start, methods=["POST"]),
    Route("/api/stream", api_stream),
    Route("/api/stop", api_stop, methods=["POST"]),
    Route("/api/sessions", api_sessions),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    print("VK Cloud Whitelist IP Roller")
    print(f"Whitelist: {len(WHITELIST)} networks")
    print(f"Open: http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
