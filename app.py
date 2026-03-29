#!/usr/bin/env python3
"""
VK Cloud Whitelist IP Roller
Web interface for finding/replacing floating IPs that fall in a CIDR whitelist.

Authentication: OpenStack permanent API token + OpenRC v3 file (auth_url, project_id, region).
Supports multiple accounts with parallel search and per-account proxy (SOCKS5/HTTP).
"""

import asyncio
import base64
import ipaddress
import json
import os
import random
import time as _time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
import uvicorn
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
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
    accounts_info: list[dict] = field(default_factory=list)
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


def ip_in_whitelist(
    ip_str: str,
    whitelist: list[ipaddress.IPv4Network] | None = None,
) -> ipaddress.IPv4Network | None:
    wl = whitelist if whitelist is not None else WHITELIST
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net in wl:
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
# Yandex Cloud auth & VPC helpers
# ---------------------------------------------------------------------------

_YC_IAM_URL = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
_YC_VPC_URL = "https://vpc.api.cloud.yandex.net/vpc/v1"
_YC_OPS_URL = "https://operation.api.cloud.yandex.net/operations"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_yc_jwt(key_id: str, sa_id: str, private_key_pem: str) -> str:
    """Create a signed RS256 JWT for Yandex Cloud service account auth."""
    header = _b64url(json.dumps(
        {"typ": "JWT", "alg": "PS256", "kid": key_id}, separators=(",", ":")
    ).encode())
    now = int(_time.time())
    payload = _b64url(json.dumps({
        "iss": sa_id,
        "aud": _YC_IAM_URL,
        "iat": now,
        "exp": now + 3600,
    }, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    signature = private_key.sign(
        signing_input,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return f"{header}.{payload}.{_b64url(signature)}"


async def get_yc_iam_token(
    client: httpx.AsyncClient,
    key_id: str,
    sa_id: str,
    private_key_pem: str,
) -> tuple[str, datetime]:
    """Exchange service account JWT for an IAM token (valid ~12 h)."""
    jwt = _make_yc_jwt(key_id, sa_id, private_key_pem)
    resp = await client.post(_YC_IAM_URL, json={"jwt": jwt}, timeout=30)
    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"Ошибка получения IAM токена YC ({resp.status_code}): {resp.text[:500]}"
        )
    data = resp.json()
    iam_token = data["iamToken"]
    expires_str = data.get("expiresAt", "")
    try:
        expires_at = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        expires_at = datetime.now(timezone.utc) + timedelta(hours=12)
    return iam_token, expires_at


async def _poll_yc_operation(
    client: httpx.AsyncClient, iam_token: str, op_id: str, timeout: float = 60.0
) -> dict:
    """Poll YC operation until done, return response dict."""
    deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout)
    while True:
        resp = await client.get(
            f"{_YC_OPS_URL}/{op_id}",
            headers={"Authorization": f"Bearer {iam_token}"},
            timeout=15,
        )
        resp.raise_for_status()
        op = resp.json()
        if op.get("done"):
            if "error" in op:
                err = op["error"]
                raise RuntimeError(
                    f"Операция YC завершилась с ошибкой {err.get('code')}: {err.get('message', str(err))}"
                )
            return op.get("response", {})
        if datetime.now(timezone.utc) >= deadline:
            raise RuntimeError(f"Таймаут ожидания операции YC {op_id}")
        await asyncio.sleep(1.0)


async def allocate_yc_address(
    client: httpx.AsyncClient, iam_token: str, folder_id: str, zone_id: str
) -> dict:
    """Allocate a new static external IP in the given zone. Returns address dict."""
    name = "roller-" + uuid.uuid4().hex[:8]
    resp = await client.post(
        f"{_YC_VPC_URL}/addresses",
        headers={"Authorization": f"Bearer {iam_token}"},
        json={
            "folderId": folder_id,
            "name": name,
            "externalIpv4AddressSpec": {"zoneId": zone_id},
        },
        timeout=30,
    )
    if resp.status_code == 429:
        retry_after = float(resp.headers.get("Retry-After", RATE_LIMIT_BASE))
        raise RateLimitError(retry_after)
    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"Не удалось выделить адрес YC ({resp.status_code}): {resp.text[:300]}"
        )
    op = resp.json()
    return await _poll_yc_operation(client, iam_token, op["id"])


async def delete_yc_address(
    client: httpx.AsyncClient, iam_token: str, address_id: str
) -> None:
    """Release a static external IP (fire-and-forget; errors are logged only)."""
    resp = await client.delete(
        f"{_YC_VPC_URL}/addresses/{address_id}",
        headers={"Authorization": f"Bearer {iam_token}"},
        timeout=30,
    )
    if resp.status_code == 404:
        print(f"[warn] YC address {address_id} уже удалён (404)")
        return
    if resp.status_code not in (200, 201, 204):
        print(f"[warn] YC DELETE {address_id} вернул {resp.status_code}: {resp.text[:200]}")


async def list_yc_addresses(
    client: httpx.AsyncClient, iam_token: str, folder_id: str
) -> list[dict]:
    resp = await client.get(
        f"{_YC_VPC_URL}/addresses",
        params={"folderId": folder_id},
        headers={"Authorization": f"Bearer {iam_token}"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("addresses", [])


# ---------------------------------------------------------------------------
# Core rolling loop — Yandex Cloud (single account)
# ---------------------------------------------------------------------------

async def run_yc_rolling_loop(
    creds: dict,
    delay_min: float,
    delay_max: float,
    proxy_url: str | None,
    account_id: str,
    long_pause_chance: float = 0.0,
    long_pause_min: float = 300.0,
    long_pause_max: float = 1200.0,
    rest_every: int = 0,
    rest_min: float = 1800.0,
    rest_max: float = 5400.0,
    start_delay: float = 0.0,
    whitelist: list[ipaddress.IPv4Network] | None = None,
):
    """
    Async generator yielding SSE events for a single Yandex Cloud account.
    Allocates static external IPs (round-robin across selected zones) until
    one matches cidrwhitelist.txt.
    """
    def ev(event: str, data) -> dict:
        return _sse_tagged(account_id, event, data)

    if start_delay > 0:
        yield ev("status", f"Ожидание старта {start_delay:.0f}с (разнос аккаунтов)...")
        await asyncio.sleep(start_delay)

    key_id = creds["key_id"]
    sa_id = creds["sa_id"]
    private_key_pem = creds["private_key"]
    folder_id = creds["folder_id"]
    zones: list[str] = creds.get("zones") or ["ru-central1-a"]
    old_ip_id: str | None = creds.get("old_ip_id") or None

    yield ev("status", "Получение IAM токена Yandex Cloud...")
    client = _make_client(proxy_url)
    try:
        try:
            iam_token, expires_at = await get_yc_iam_token(client, key_id, sa_id, private_key_pem)
        except Exception as e:
            yield ev("error", f"Ошибка аутентификации YC: {e}")
            return

        yield ev("status", f"IAM токен получен. Зоны: {', '.join(zones)}")
        # Refresh 1-2 h before expiry (token lives 12 h)
        refresh_at = expires_at - timedelta(seconds=random.uniform(3600, 7200))

        # Replace mode: delete old IP first
        if old_ip_id:
            yield ev("status", f"Удаляем выбранный адрес {old_ip_id}...")
            try:
                await delete_yc_address(client, iam_token, old_ip_id)
                old_ip_id = None
                yield ev("status", "Удалён. Начинаем поиск замены...")
            except Exception as e:
                yield ev("error", f"Не удалось удалить выбранный адрес: {e}")
                return

        attempt = 0
        prev_addr: dict | None = None  # {"id": ..., "ip": ...}
        zone_idx = 0
        rate_limit_wait = RATE_LIMIT_BASE

        try:
            while True:
                # Proactive IAM token refresh
                if datetime.now(timezone.utc) >= refresh_at:
                    yield ev("status", "Обновление IAM токена...")
                    refresh_ok = False
                    for _retry in range(3):
                        try:
                            iam_token, expires_at = await get_yc_iam_token(
                                client, key_id, sa_id, private_key_pem
                            )
                            refresh_at = expires_at - timedelta(seconds=random.uniform(3600, 7200))
                            yield ev("status", "IAM токен обновлён.")
                            refresh_ok = True
                            break
                        except Exception as e:
                            if _retry < 2:
                                wait = 30 * (_retry + 1)
                                yield ev("status",
                                         f"Ошибка обновления токена (попытка {_retry + 1}/3),"
                                         f" повтор через {wait}с: {e}")
                                await asyncio.sleep(wait)
                            else:
                                yield ev("error", f"Ошибка обновления IAM токена: {e}")
                    if not refresh_ok:
                        return

                attempt += 1
                zone_id = zones[zone_idx % len(zones)]
                zone_idx += 1

                # Delete previous non-matching address
                if prev_addr:
                    yield ev("status", f"Удаляем {prev_addr['ip']}...")
                    await delete_yc_address(client, iam_token, prev_addr["id"])
                    prev_addr = None
                    delay = random.uniform(delay_min, delay_max)
                    yield ev("status", f"Пауза {delay:.1f}с...")
                    await asyncio.sleep(delay)

                yield ev("status", f"Попытка {attempt} (зона {zone_id})...")

                # Allocate with rate-limit retry
                while True:
                    try:
                        addr = await allocate_yc_address(client, iam_token, folder_id, zone_id)
                        rate_limit_wait = RATE_LIMIT_BASE
                        break
                    except RateLimitError as e:
                        yield ev("status",
                                 f"Лимит запросов API (429) — пауза {e.wait:.0f}с...")
                        await asyncio.sleep(e.wait)
                        rate_limit_wait = min(rate_limit_wait * 2, RATE_LIMIT_MAX)
                    except Exception as e:
                        yield ev("error", f"Ошибка выделения адреса YC: {e}")
                        return

                ip_str = addr.get("externalIpv4Address", {}).get("address", "")
                matched_net = ip_in_whitelist(ip_str, whitelist)

                yield ev("attempt", {
                    "n": attempt,
                    "ip": ip_str,
                    "id": addr.get("id", ""),
                    "match": str(matched_net) if matched_net else None,
                    "zone": zone_id,
                })

                if matched_net:
                    yield ev("success", {
                        "ip": ip_str,
                        "id": addr.get("id", ""),
                        "network": str(matched_net),
                        "attempts": attempt,
                        "zone": zone_id,
                    })
                    return
                else:
                    prev_addr = {"id": addr.get("id", ""), "ip": ip_str}
                    if long_pause_chance > 0 and random.random() < long_pause_chance:
                        lp = random.uniform(long_pause_min, long_pause_max)
                        yield ev("status",
                                 f"Длинная пауза {lp/60:.1f} мин. (антиблок)...")
                        await asyncio.sleep(lp)
                    if rest_every > 0 and attempt % rest_every == 0:
                        rest = random.uniform(rest_min, rest_max)
                        yield ev("status",
                                 f"Плановый отдых {rest/60:.0f} мин. (каждые {rest_every} попыток)...")
                        await asyncio.sleep(rest)

        except asyncio.CancelledError:
            if prev_addr:
                try:
                    await delete_yc_address(client, iam_token, prev_addr["id"])
                except Exception:
                    pass
            raise
        except Exception as e:
            if prev_addr:
                try:
                    await delete_yc_address(client, iam_token, prev_addr["id"])
                except Exception:
                    pass
            yield ev("error", f"Ошибка: {e}")

    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Core rolling loop — VK Cloud (single account)
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
    rest_every: int = 0,
    rest_min: float = 1800.0,
    rest_max: float = 5400.0,
    start_delay: float = 0.0,
    whitelist: list[ipaddress.IPv4Network] | None = None,
):
    """
    Async generator that yields SSE events tagged with account_id.
    Allocates floating IPs until one matches the whitelist.
    If old_ip_id is given, deletes it first (replace mode).
    """
    def ev(event: str, data) -> dict:
        return _sse_tagged(account_id, event, data)

    if start_delay > 0:
        yield ev("status", f"Ожидание старта {start_delay:.0f}с (разнос аккаунтов)...")
        await asyncio.sleep(start_delay)

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
                    refresh_ok = False
                    for _retry in range(3):
                        try:
                            scoped_token, neutron_url, expires_at = await get_scoped_token(
                                client, creds["auth_url"], creds["project_id"],
                                creds["region"], creds["api_token"],
                            )
                            refresh_at = expires_at - timedelta(seconds=random.uniform(120, 600))
                            yield ev("status", "Токен обновлён.")
                            refresh_ok = True
                            break
                        except Exception as e:
                            if _retry < 2:
                                wait = 30 * (_retry + 1)
                                yield ev("status",
                                         f"Ошибка обновления токена (попытка {_retry + 1}/3),"
                                         f" повтор через {wait}с: {e}")
                                await asyncio.sleep(wait)
                            else:
                                yield ev("error", f"Ошибка обновления токена: {e}")
                    if not refresh_ok:
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
                matched_net = ip_in_whitelist(ip_str, whitelist)

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
                    # Mandatory periodic rest after every N attempts
                    if rest_every > 0 and attempt % rest_every == 0:
                        rest = random.uniform(rest_min, rest_max)
                        yield ev("status",
                                 f"Плановый отдых {rest/60:.0f} мин. (каждые {rest_every} попыток)...")
                        await asyncio.sleep(rest)

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
    rest_every = int(body.get("rest_every", 0))
    rest_min = float(body.get("rest_min", 30)) * 60.0
    rest_max = float(body.get("rest_max", 90)) * 60.0

    if not accounts:
        return JSONResponse({"error": "Не передано ни одного аккаунта"}, status_code=400)

    _required_vk = ("auth_url", "project_id", "region", "api_token")
    _required_yc = ("key_id", "sa_id", "private_key", "folder_id")
    for acc in accounts:
        required = _required_yc if acc.get("type") == "yc" else _required_vk
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

    # Parse custom whitelist if provided, else use global
    session_whitelist: list[ipaddress.IPv4Network] | None = None
    custom_whitelist_raw = body.get("custom_whitelist")
    if custom_whitelist_raw:
        parsed_wl = []
        for cidr in custom_whitelist_raw:
            try:
                parsed_wl.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
            except ValueError:
                pass
        if parsed_wl:
            session_whitelist = parsed_wl

    session_id = str(uuid.uuid4())
    session = Session(id=session_id)
    session.accounts_info = [
        {"id": acc["id"], "name": acc.get("name", acc["id"])}
        for acc in accounts
    ]
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

    async def _acc_worker(acc: dict, start_delay: float = 0.0) -> None:
        common = dict(
            delay_min=delay_min,
            delay_max=delay_max,
            proxy_url=acc.get("proxy_url") or None,
            account_id=acc["id"],
            long_pause_chance=long_pause_chance,
            long_pause_min=long_pause_min,
            long_pause_max=long_pause_max,
            rest_every=rest_every,
            rest_min=rest_min,
            rest_max=rest_max,
            start_delay=start_delay,
            whitelist=session_whitelist,
        )
        try:
            if acc.get("type") == "yc":
                gen = run_yc_rolling_loop(creds=acc, **common)
            else:
                gen = run_rolling_loop(
                    creds=acc, old_ip_id=acc.get("old_ip_id") or None, **common
                )
            async for event in gen:
                _push(event)
        except asyncio.CancelledError:
            pass
        finally:
            _account_done()

    for i, acc in enumerate(accounts):
        stagger = 0.0 if i == 0 else i * random.uniform(15, 45)
        task = asyncio.create_task(_acc_worker(acc, start_delay=stagger))
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
        {"session_id": s.id, "done": s.done, "events": len(s.events), "accounts": s.accounts_info}
        for s in SESSIONS.values()
    ]
    return JSONResponse({"sessions": active})


async def api_stop_all(request: Request) -> JSONResponse:
    """Cancel all tasks for all sessions."""
    count = len(SESSIONS)
    for session in list(SESSIONS.values()):
        for task in session.tasks:
            task.cancel()
    SESSIONS.clear()
    return JSONResponse({"ok": True, "stopped": count})


async def api_whitelist_info(request: Request) -> JSONResponse:
    """Return default whitelist network count."""
    return JSONResponse({"count": len(WHITELIST), "file": WHITELIST_FILE.name})


async def api_yc_ips(request: Request) -> JSONResponse:
    """Return list of Yandex Cloud static external IP addresses for one account."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Неверный JSON"}, status_code=400)

    key_id = (body.get("key_id") or "").strip()
    sa_id = (body.get("sa_id") or "").strip()
    private_key = (body.get("private_key") or "").strip()
    folder_id = (body.get("folder_id") or "").strip()
    proxy_url = body.get("proxy_url") or None

    missing = [k for k, v in {"key_id": key_id, "sa_id": sa_id,
                               "private_key": private_key, "folder_id": folder_id}.items() if not v]
    if missing:
        return JSONResponse({"error": f"Не заполнены поля: {missing}"}, status_code=400)

    try:
        async with _make_client(proxy_url) as client:
            iam_token, _ = await get_yc_iam_token(client, key_id, sa_id, private_key)
            addresses = await list_yc_addresses(client, iam_token, folder_id)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    return JSONResponse({"ips": [
        {
            "id": a["id"],
            "ip": a.get("externalIpv4Address", {}).get("address", ""),
            "zone": a.get("externalIpv4Address", {}).get("zoneId", ""),
            "status": "USED" if a.get("used") else "FREE",
        }
        for a in addresses
    ]})


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
    Route("/api/stop-all", api_stop_all, methods=["POST"]),
    Route("/api/sessions", api_sessions),
    Route("/api/yc-ips", api_yc_ips, methods=["POST"]),
    Route("/api/whitelist-info", api_whitelist_info),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    print("VK Cloud Whitelist IP Roller")
    print(f"Whitelist: {len(WHITELIST)} networks")
    print(f"Open: http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
