"""Remnawave subscription manager.

Прокси над подпиской Remnawave:
- VPN-клиент дёргает /{token} -> отдаём base64 список vless + сторонние сервера из БД;
- браузер открывает /{token} -> отдаём HTML-страницу с кнопками «добавить» и QR.

Запуск: uvicorn manager:app --host 0.0.0.0 --port 8080
"""

import base64
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from settings.config import config
import db
import panel

app = FastAPI(title="Remnawave Sub Manager")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Белый список заголовков подписки. "announce" обязателен (Happ опознаёт сабку).
# "routing" (happ-роутинг) большой (~1.5КБ) и при HTTP/2 Caddy рвёт Happ
# ("socket closed") — содержимое идентично nginx, проблема в h2-транспорте,
# поэтому Caddy переведён на HTTP/1.1 (см. Caddyfile: protocols h1).
PASSTHROUGH_HEADERS = (
    "content-disposition",
    "profile-title",
    "profile-update-interval",
    "subscription-userinfo",
    "profile-web-page-url",
    "support-url",
    "announce",
    "routing",
)


def _passthrough_headers(up: "httpx.Response") -> dict:
    return {k: up.headers[k] for k in PASSTHROUGH_HEADERS if k in up.headers}

# UA известных VPN-клиентов — им всегда отдаём конфиг, не HTML.
CLIENT_UA_KEYWORDS = (
    "v2ray", "clash", "sing-box", "singbox", "hiddify", "streisand",
    "shadowrocket", "nekobox", "nekoray", "foxray", "v2box", "happ",
    "throne", "ktor", "go-http", "python-httpx", "okhttp",
)


@app.on_event("startup")
def _startup() -> None:
    db.init_db(seed_file=config.EXTRA_FILE)


def wants_html(request: Request) -> bool:
    """Браузер (HTML + Mozilla UA, не VPN-клиент) -> показываем страницу."""
    ua = request.headers.get("user-agent", "").lower()
    accept = request.headers.get("accept", "").lower()
    if any(k in ua for k in CLIENT_UA_KEYWORDS):
        return False
    return "text/html" in accept and "mozilla" in ua


def b64_decode(text: str) -> list[str]:
    """Декод base64-сабки в список ссылок. Кидает исключение, если не base64."""
    text = text.strip()
    pad = "=" * (-len(text) % 4)
    raw = base64.b64decode(text + pad).decode("utf-8")
    return [ln for ln in raw.splitlines() if ln.strip()]


def b64_encode(links: list[str]) -> str:
    return base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} EB"


def parse_userinfo(headers) -> dict | None:
    """Распарсить subscription-userinfo: трафик и срок подписки."""
    raw = headers.get("subscription-userinfo")
    if not raw:
        return None
    d = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            d[k.strip()] = v.strip()
    try:
        up = int(d.get("upload", 0))
        down = int(d.get("download", 0))
        total = int(d.get("total", 0))
        expire = int(d.get("expire", 0))
    except ValueError:
        return None

    used = up + down
    info = {
        "used": _human_bytes(used),
        "total": "∞" if total == 0 else _human_bytes(total),
        "unlimited": total == 0,
        "used_pct": 0 if total == 0 else min(100, round(used / total * 100)),
    }
    if expire == 0:
        info.update(expire_str="бессрочно", days_left=None, expired=False)
    else:
        from datetime import datetime, timezone

        dt = datetime.fromtimestamp(expire, tz=timezone.utc)
        days = (dt - datetime.now(timezone.utc)).days
        info.update(
            expire_str=dt.strftime("%d.%m.%Y"),
            days_left=days,
            expired=days < 0,
        )
    return info


def decode_profile_title(headers) -> str | None:
    """profile-title приходит как 'base64:...' — раскодировать."""
    t = headers.get("profile-title")
    if not t:
        return None
    if t.startswith("base64:"):
        try:
            return base64.b64decode(t[7:]).decode("utf-8")
        except Exception:
            return None
    return t


# Публичный ключ Happ v4 — для шифрованной deep-link подписки happ://crypt4/.
# Happ импортирует подписку по URL только через RSA-зашифрованную ссылку.
_HAPP_PUBKEY_V4 = b"""-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3UZ0M3L4K+WjM3vkbQnz
ozHg/cRbEXvQ6i4A8RVN4OM3rK9kU01FdjyoIgywve8OEKsFnVwERZAQZ1Trv60B
hmaM76QQEE+EUlIOL9EpwKWGtTL5lYC1sT9XJMNP3/CI0gP5wwQI88cY/xedpOEB
W72EmOOShHUm/b/3m+HPmqwc4ugKj5zWV5SyiT829aFA5DxSjmIIFBAms7DafmSq
LFTYIQL5cShDY2u+/sqyAw9yZIOoqW2TFIgIHhLPWek/ocDU7zyOrlu1E0SmcQQb
LFqHq02fsnH6IcqTv3N5Adb/CkZDDQ6HvQVBmqbKZKf7ZdXkqsc/Zw27xhG7OfXC
tUmWsiL7zA+KoTd3avyOh93Q9ju4UQsHthL3Gs4vECYOCS9dsXXSHEY/1ngU/hjO
WFF8QEE/rYV6nA4PTyUvo5RsctSQL/9DJX7XNh3zngvif8LsCN2MPvx6X+zLouBX
zgBkQ9DFfZAGLWf9TR7KVjZC/3NsuUCDoAOcpmN8pENBbeB0puiKMMWSvll36+2M
YR1Xs0MgT8Y9TwhE2+TnnTJOhzmHi/BxiUlY/w2E0s4ax9GHAmX0wyF4zeV7kDkc
vHuEdc0d7vDmdw0oqCqWj0Xwq86HfORu6tm1A8uRATjb4SzjTKclKuoElVAVa5Jo
oh/uZMozC65SmDw+N5p6Su8CAwEAAQ==
-----END PUBLIC KEY-----"""

_happ_key = None


def happ_crypt_link(sub_url: str) -> str:
    """happ://crypt4/<urlencode(base64(RSA-PKCS1v15(sub_url, happ_pubkey)))>."""
    global _happ_key
    if _happ_key is None:
        _happ_key = load_pem_public_key(_HAPP_PUBKEY_V4)
    ct = _happ_key.encrypt(sub_url.encode("utf-8"), rsa_padding.PKCS1v15())
    return "happ://crypt4/" + quote(base64.b64encode(ct).decode("ascii"), safe="")


def build_apps(sub_url: str, enc: str) -> list[tuple[str, str]]:
    """Deep-link'и импорта подписки под популярные клиенты (правильные схемы)."""
    return [
        ("Happ", happ_crypt_link(sub_url)),
        ("v2rayNG", f"v2rayng://install-sub?url={enc}"),
        ("v2RayTun", f"v2raytun://import/{sub_url}"),
        ("Hiddify", f"hiddify://import/{sub_url}"),
        ("Streisand", f"streisand://import/{sub_url}"),
        ("Clash Meta", f"clash://install-config?url={enc}"),
        ("Sing-box", f"sing-box://import-remote-profile?url={enc}"),
        ("Karing", f"karing://install-config?url={enc}"),
    ]


async def fetch_upstream(
    token: str, request: Request, ua: str | None = None
) -> httpx.Response:
    # ua override: для инфо-страницы шлём клиентский UA, иначе upstream на
    # браузерный UA отдаёт HTML-редирект без заголовков подписки.
    fwd_headers = {
        "User-Agent": ua or request.headers.get("user-agent", "RemnawaveSubManager"),
        "Accept": request.headers.get("accept", "*/*"),
    }
    if config.UPSTREAM_COOKIE:
        fwd_headers["Cookie"] = config.UPSTREAM_COOKIE
    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        return await client.get(f"{config.UPSTREAM_URL}/{token}", headers=fwd_headers)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "extra_servers": len(db.get_enabled_links())}


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Админка серверов
# ---------------------------------------------------------------------------

def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    """Проверка админ-токена для API-эндпоинтов (header X-Admin-Token)."""
    if not config.ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="ADMIN_TOKEN not configured")
    if x_admin_token != config.ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="invalid admin token")


class ServerIn(BaseModel):
    link: str
    name: str | None = None
    enabled: bool = True
    is_global: bool = True


class ServerPatch(BaseModel):
    link: str | None = None
    name: str | None = None
    enabled: bool | None = None
    is_global: bool | None = None


class AssignIn(BaseModel):
    server_ids: list[int]


def _server_dict(s: db.ExtraServer) -> dict:
    return {
        "id": s.id,
        "link": s.link,
        "name": s.name,
        "enabled": s.enabled,
        "is_global": s.is_global,
    }


@app.get("/admin", include_in_schema=False)
async def admin_page(request: Request, key: str | None = None):
    if not config.ADMIN_TOKEN or key != config.ADMIN_TOKEN:
        return Response("forbidden", status_code=403)
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"brand": config.BRAND, "key": config.ADMIN_TOKEN},
    )


@app.get("/admin/servers", dependencies=[Depends(require_admin)])
async def admin_list():
    return [_server_dict(s) for s in db.list_servers()]


@app.post("/admin/servers", dependencies=[Depends(require_admin)])
async def admin_create(body: ServerIn):
    s = db.add_server(
        link=body.link.strip(),
        name=body.name,
        enabled=body.enabled,
        is_global=body.is_global,
    )
    return _server_dict(s)


@app.patch("/admin/servers/{server_id}", dependencies=[Depends(require_admin)])
async def admin_update(server_id: int, body: ServerPatch):
    new_link = body.link.strip() if body.link is not None else None

    # Имя в VPN-клиенте берётся из #-метки самой vless-ссылки.
    # Поэтому при смене name переписываем и фрагмент ссылки, чтобы
    # имя менялось в обоих местах (таблица + конфиг у юзера).
    if body.name is not None:
        current = db.get_server(server_id)
        if current is None:
            raise HTTPException(status_code=404, detail="server not found")
        base = (new_link if new_link is not None else current.link).split("#", 1)[0]
        new_link = f"{base}#{body.name}"

    s = db.update_server(
        server_id,
        link=new_link,
        name=body.name,
        enabled=body.enabled,
        is_global=body.is_global,
    )
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    return _server_dict(s)


@app.delete("/admin/servers/{server_id}", dependencies=[Depends(require_admin)])
async def admin_delete(server_id: int):
    if not db.delete_server(server_id):
        raise HTTPException(status_code=404, detail="server not found")
    return {"deleted": server_id}


# ---- Пользователи панели + персональные назначения --------------------------

@app.get("/admin/users", dependencies=[Depends(require_admin)])
async def admin_users():
    """Список юзеров панели + готовая sub-manager ссылка."""
    try:
        users = await panel.list_users()
    except panel.PanelError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    for u in users:
        u["sub_url"] = f"{config.PUBLIC_URL}/{u['short_uuid']}"
        u["assigned"] = db.list_assignments(u["short_uuid"])
    return users


@app.get("/admin/users/{token}/servers", dependencies=[Depends(require_admin)])
async def admin_user_servers(token: str):
    """ID персональных серверов, назначенных юзеру."""
    return {"token": token, "assigned": db.list_assignments(token)}


@app.put("/admin/users/{token}/servers", dependencies=[Depends(require_admin)])
async def admin_user_assign(token: str, body: AssignIn):
    """Заменить набор персональных серверов юзера."""
    assigned = db.set_assignments(token, body.server_ids)
    return {"token": token, "assigned": assigned}


def _raw_subscription(up: httpx.Response, token: str) -> Response:
    # Пробрасываем все заголовки апстрима (happ-routing, subscription-userinfo и т.д.).
    headers = _passthrough_headers(up)
    try:
        links = b64_decode(up.text)
    except Exception:
        # Не base64 (clash/sing-box yaml) — мёрж не поддержан, отдаём как есть.
        headers.setdefault("content-type", "text/plain; charset=utf-8")
        return Response(content=up.content, status_code=up.status_code, headers=headers)
    # глобальные сервера + персонально назначенные этому токену
    links += db.get_links_for_token(token)
    headers["content-type"] = up.headers.get("content-type", "text/plain; charset=utf-8")
    return Response(content=b64_encode(links), headers=headers)


@app.get("/{token}")
async def manage(token: str, request: Request):
    if not config.UPSTREAM_URL:
        return Response("UPSTREAM_URL not configured", status_code=500)

    db.touch_subscription(token)

    # Браузер -> HTML-страница. Дёргаем upstream, чтобы достать инфо подписки
    # (трафик/срок из subscription-userinfo, имя из profile-title).
    if wants_html(request):
        sub_url = f"{config.PUBLIC_URL}/{token}"
        enc = quote(sub_url, safe="")
        info = None
        title = None
        try:
            up = await fetch_upstream(token, request, ua="Happ/manager")
            info = parse_userinfo(up.headers)
            title = decode_profile_title(up.headers)
        except httpx.HTTPError:
            pass
        return templates.TemplateResponse(
            request=request,
            name="subscription.html",
            context={
                "brand": config.BRAND,
                "title": title,
                "info": info,
                "sub_url": sub_url,
                "enc": enc,
                "apps": build_apps(sub_url, enc),
            },
        )

    # VPN-клиент -> конфиг.
    try:
        up = await fetch_upstream(token, request)
    except httpx.HTTPError as exc:
        return Response(f"upstream error: {exc}", status_code=502)
    return _raw_subscription(up, token)
