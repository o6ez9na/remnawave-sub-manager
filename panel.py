"""Клиент API панели Remnawave — список пользователей."""

import httpx

from settings.config import config


class PanelError(RuntimeError):
    pass


def _headers() -> dict:
    if not config.PANEL_API_KEY:
        raise PanelError("REMNAWAVE_API_KEY not configured")
    if not config.PANEL_API_KEY.isascii():
        raise PanelError(
            "REMNAWAVE_API_KEY содержит не-ASCII символы — похоже, в .env остался "
            "плейсхолдер. Впиши настоящий API-токен из панели."
        )
    h = {
        "Authorization": f"Bearer {config.PANEL_API_KEY}",
        "Accept": "application/json",
        "User-Agent": "RemnawaveSubManager",
    }
    # eGames прячет панель за cookie rEmnaprx=<SECRET_KEY>; без него снаружи 404.
    if config.PANEL_COOKIE:
        h["Cookie"] = config.PANEL_COOKIE
    # Необязательный caddy-токен в X-Api-Key (если у твоей сборки он используется).
    if config.PANEL_CADDY_TOKEN:
        h["X-Api-Key"] = config.PANEL_CADDY_TOKEN
    return h


def _short_uuid(u: dict) -> str | None:
    """Токен подписки = shortUuid; если нет — берём хвост subscriptionUrl."""
    if u.get("shortUuid"):
        return u["shortUuid"]
    sub = u.get("subscriptionUrl")
    if sub:
        return sub.rstrip("/").rsplit("/", 1)[-1]
    return None


async def list_users(limit: int = 500) -> list[dict]:
    """Вернуть упрощённый список юзеров: username, short_uuid, status, expire_at."""
    if not config.PANEL_URL:
        raise PanelError("PANEL_URL not configured")

    url = f"{config.PANEL_URL}/users"
    params = {"size": limit, "start": 0}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20) as client:
            r = await client.get(url, headers=_headers(), params=params)
    except PanelError:
        raise
    except Exception as exc:  # сеть, кодировка заголовков и т.п.
        raise PanelError(f"panel request failed: {exc}") from exc
    if r.status_code == 401:
        raise PanelError("panel auth failed (401) — проверь REMNAWAVE_API_KEY / PANEL_COOKIE")
    if r.status_code >= 400:
        raise PanelError(f"panel error {r.status_code}: {r.text[:200]}")

    data = r.json()
    users = data.get("response", {}).get("users") or data.get("users") or []

    out = []
    for u in users:
        short = _short_uuid(u)
        if not short:
            continue
        out.append(
            {
                "username": u.get("username"),
                "short_uuid": short,
                "status": u.get("status"),
                "expire_at": u.get("expireAt"),
                "telegram_id": u.get("telegramId"),
            }
        )
    return out
