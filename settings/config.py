from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    URI = os.getenv('URI')
    RW_LOGIN = os.getenv('RW_LOGIN')
    RW_PASSWORD = os.getenv('RW_PASSWORD')

    # Базовый URL подписок Remnawave (без завершающего слэша),
    # например https://mint-sub.atlas.gripe
    UPSTREAM_URL = (os.getenv('UPSTREAM_URL') or '').rstrip('/')
    # Путь к файлу со сторонними vless-ссылками
    EXTRA_FILE = os.getenv('EXTRA_FILE', 'extra_servers.txt')
    # Cookie для eGames reverse-proxy в формате NAME=VALUE (опционально)
    UPSTREAM_COOKIE = os.getenv('UPSTREAM_COOKIE')

    # База данных (SQLite по умолчанию, лежит в ./data для docker-volume)
    DB_URL = os.getenv('DB_URL', 'sqlite:///data/manager.db')
    # Публичный базовый URL менеджера (для ссылок/QR на странице подписки)
    PUBLIC_URL = (os.getenv('PUBLIC_URL') or 'http://localhost:8080').rstrip('/')
    # Название бренда на странице подписки
    BRAND = os.getenv('BRAND', 'VPN')
    # Токен доступа к админ-панели серверов (обязателен для /admin)
    ADMIN_TOKEN = os.getenv('ADMIN_TOKEN')

    # Доступ к API панели Remnawave (для списка пользователей).
    # PANEL_URL — базовый URL с /api, например https://mint-panel.atlas.gripe/api
    PANEL_URL = (os.getenv('PANEL_URL') or URI or '').rstrip('/')
    # Bearer-токен API панели (раздел API Tokens в Remnawave)
    PANEL_API_KEY = os.getenv('REMNAWAVE_API_KEY')
    # eGames Caddy-токен (шлётся в X-Api-Key, обходит защиту панели).
    # Берётся из конфига бота REMNAWAVE_CADDY_TOKEN.
    PANEL_CADDY_TOKEN = os.getenv('REMNAWAVE_CADDY_TOKEN')
    # Cookie панели в формате NAME=VALUE (опционально, для cookie-режима eGames)
    PANEL_COOKIE = os.getenv('PANEL_COOKIE')

config = Config()