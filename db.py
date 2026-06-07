"""База данных менеджера подписок (SQLite через SQLModel)."""

from datetime import datetime
from pathlib import Path

from sqlalchemy import inspect, text
from sqlmodel import Field, SQLModel, Session, create_engine, select

from settings.config import config


class ExtraServer(SQLModel, table=True):
    """Сторонний сервер.

    is_global=True -> добавляется в подписку каждого юзера.
    is_global=False -> персональный, попадает только тем, кому назначен
    (см. UserAssignment).

    source_id != None -> сервер пришёл из импортированной подписки и
    авто-обновляется по ckey (идентичность: scheme+uuid+host:port).
    """

    id: int | None = Field(default=None, primary_key=True)
    link: str
    name: str | None = None
    enabled: bool = True
    is_global: bool = True
    source_id: int | None = Field(default=None, index=True)
    ckey: str | None = None
    position: int = Field(default=0, index=True)


class ImportSource(SQLModel, table=True):
    """Ссылка-источник подписки, которую раз в час перепарсиваем."""

    id: int | None = Field(default=None, primary_key=True)
    url: str
    is_global: bool = True
    last_synced: datetime | None = None
    last_count: int = 0


class UserAssignment(SQLModel, table=True):
    """Связка: отдельный персональный сервер -> юзер (для ручных серверов)."""

    id: int | None = Field(default=None, primary_key=True)
    user_token: str = Field(index=True)
    server_id: int = Field(index=True)


class UserSource(SQLModel, table=True):
    """Связка: источник-подписка целиком -> юзер.

    Юзер получает ВСЕ включённые сервера источника. Набор авто-следует за
    обновлениями источника (привязка по source_id, а не по id сервера).
    """

    id: int | None = Field(default=None, primary_key=True)
    user_token: str = Field(index=True)
    source_id: int = Field(index=True)


class Subscription(SQLModel, table=True):
    """Реестр токенов, которые проходили через менеджер (для статистики/гейта)."""

    token: str = Field(primary_key=True)
    title: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


# Для sqlite-файла создаём каталог заранее.
if config.DB_URL.startswith("sqlite:///"):
    db_path = Path(config.DB_URL.removeprefix("sqlite:///"))
    db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    config.DB_URL,
    connect_args={"check_same_thread": False} if config.DB_URL.startswith("sqlite") else {},
)


def _migrate() -> None:
    """Лёгкая миграция: добить недостающие колонки в extraserver."""
    insp = inspect(engine)
    if "extraserver" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("extraserver")}
    is_sqlite = config.DB_URL.startswith("sqlite")
    stmts = []
    if "is_global" not in cols:
        stmts.append(f"ALTER TABLE extraserver ADD COLUMN is_global BOOLEAN DEFAULT {'1' if is_sqlite else 'true'}")
    if "source_id" not in cols:
        stmts.append("ALTER TABLE extraserver ADD COLUMN source_id INTEGER")
    if "ckey" not in cols:
        stmts.append("ALTER TABLE extraserver ADD COLUMN ckey VARCHAR")
    add_position = "position" not in cols
    if add_position:
        stmts.append("ALTER TABLE extraserver ADD COLUMN position INTEGER DEFAULT 0")
    if stmts:
        with engine.begin() as conn:
            for s in stmts:
                conn.execute(text(s))
            if add_position:
                # начальный порядок = по id
                conn.execute(text("UPDATE extraserver SET position = id"))


def init_db(seed_file: str | None = None) -> None:
    """Создать таблицы, мигрировать и (если пусто) засеять сервера из файла."""
    SQLModel.metadata.create_all(engine)
    _migrate()
    if not seed_file:
        return
    path = Path(seed_file)
    if not path.exists():
        return
    with Session(engine) as session:
        existing = session.exec(select(ExtraServer)).first()
        if existing:
            return  # уже засеяно — файл больше не трогаем, рулим через БД
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = line.split("#", 1)[1].strip() if "#" in line else None
            session.add(ExtraServer(link=line, name=name, enabled=True, is_global=True))
        session.commit()


def get_enabled_links() -> list[str]:
    """Глобальные включённые ссылки (попадают всем)."""
    with Session(engine) as session:
        rows = session.exec(
            select(ExtraServer).where(
                ExtraServer.enabled == True, ExtraServer.is_global == True  # noqa: E712
            ).order_by(ExtraServer.position, ExtraServer.id)
        ).all()
        return [r.link for r in rows]


def get_links_for_token(user_token: str) -> list[str]:
    """Ссылки для подписки юзера: глобальные + назначенные источники +
    индивидуально назначенные ручные сервера. Дедуп по ссылке."""
    with Session(engine) as session:
        links: list[str] = []
        seen: set[str] = set()

        def add(rows):
            for r in rows:
                if r.link not in seen:
                    seen.add(r.link)
                    links.append(r.link)

        # глобальные
        add(session.exec(
            select(ExtraServer).where(
                ExtraServer.enabled == True, ExtraServer.is_global == True  # noqa: E712
            ).order_by(ExtraServer.position, ExtraServer.id)
        ).all())

        # сервера назначенных источников (целиком)
        source_ids = session.exec(
            select(UserSource.source_id).where(UserSource.user_token == user_token)
        ).all()
        if source_ids:
            add(session.exec(
                select(ExtraServer).where(
                    ExtraServer.source_id.in_(source_ids),  # type: ignore[attr-defined]
                    ExtraServer.enabled == True,  # noqa: E712
                ).order_by(ExtraServer.position, ExtraServer.id)
            ).all())

        # индивидуально назначенные персональные сервера (ручные, без источника)
        assigned_ids = session.exec(
            select(UserAssignment.server_id).where(UserAssignment.user_token == user_token)
        ).all()
        if assigned_ids:
            add(session.exec(
                select(ExtraServer).where(
                    ExtraServer.id.in_(assigned_ids),  # type: ignore[attr-defined]
                    ExtraServer.enabled == True,  # noqa: E712
                )
            ).all())
        return links


def list_servers() -> list[ExtraServer]:
    with Session(engine) as session:
        return list(
            session.exec(
                select(ExtraServer).order_by(ExtraServer.position, ExtraServer.id)
            ).all()
        )


def _next_position(session) -> int:
    rows = session.exec(select(ExtraServer.position)).all()
    return (max(rows) + 1) if rows else 0


def reorder_servers(ids: list[int]) -> None:
    """Задать порядок серверов по списку id (позиция = индекс в списке)."""
    with Session(engine) as session:
        for pos, sid in enumerate(ids):
            s = session.get(ExtraServer, sid)
            if s is not None:
                s.position = pos
                session.add(s)
        session.commit()


def move_server(server_id: int, direction: str) -> bool:
    """Переместить сервер вверх/вниз — обмен позиции с соседом по порядку."""
    with Session(engine) as session:
        ordered = session.exec(
            select(ExtraServer).order_by(ExtraServer.position, ExtraServer.id)
        ).all()
        idx = next((i for i, s in enumerate(ordered) if s.id == server_id), None)
        if idx is None:
            return False
        j = idx - 1 if direction == "up" else idx + 1
        if j < 0 or j >= len(ordered):
            return False
        a, b = ordered[idx], ordered[j]
        a.position, b.position = b.position, a.position
        session.add(a)
        session.add(b)
        session.commit()
        return True


def all_links() -> list[str]:
    """Все ссылки в БД (для дедупликации при импорте)."""
    with Session(engine) as session:
        return [r.link for r in session.exec(select(ExtraServer)).all()]


def get_server(server_id: int) -> ExtraServer | None:
    with Session(engine) as session:
        return session.get(ExtraServer, server_id)


def add_server(
    link: str, name: str | None = None, enabled: bool = True, is_global: bool = True
) -> ExtraServer:
    with Session(engine) as session:
        server = ExtraServer(
            link=link, name=name, enabled=enabled, is_global=is_global,
            position=_next_position(session),
        )
        session.add(server)
        session.commit()
        session.refresh(server)
        return server


def update_server(
    server_id: int,
    link: str | None = None,
    name: str | None = None,
    enabled: bool | None = None,
    is_global: bool | None = None,
) -> ExtraServer | None:
    with Session(engine) as session:
        server = session.get(ExtraServer, server_id)
        if server is None:
            return None
        if link is not None:
            server.link = link
        if name is not None:
            server.name = name
        if enabled is not None:
            server.enabled = enabled
        if is_global is not None:
            server.is_global = is_global
        session.add(server)
        session.commit()
        session.refresh(server)
        return server


def delete_server(server_id: int) -> bool:
    with Session(engine) as session:
        server = session.get(ExtraServer, server_id)
        if server is None:
            return False
        session.delete(server)
        session.commit()
        return True


def list_assignments(user_token: str) -> list[int]:
    """ID персональных серверов, назначенных юзеру."""
    with Session(engine) as session:
        return list(
            session.exec(
                select(UserAssignment.server_id).where(
                    UserAssignment.user_token == user_token
                )
            ).all()
        )


def set_assignments(user_token: str, server_ids: list[int]) -> list[int]:
    """Полностью заменить набор назначенных серверов для юзера."""
    wanted = set(server_ids)
    with Session(engine) as session:
        current = session.exec(
            select(UserAssignment).where(UserAssignment.user_token == user_token)
        ).all()
        have = {a.server_id for a in current}
        for a in current:
            if a.server_id not in wanted:
                session.delete(a)
        for sid in wanted - have:
            session.add(UserAssignment(user_token=user_token, server_id=sid))
        session.commit()
    return sorted(wanted)


def add_source(url: str, is_global: bool = True) -> ImportSource:
    with Session(engine) as session:
        src = ImportSource(url=url, is_global=is_global)
        session.add(src)
        session.commit()
        session.refresh(src)
        return src


def list_sources() -> list[ImportSource]:
    with Session(engine) as session:
        return list(session.exec(select(ImportSource).order_by(ImportSource.id)).all())


def get_source(source_id: int) -> ImportSource | None:
    with Session(engine) as session:
        return session.get(ImportSource, source_id)


def find_source_by_url(url: str) -> ImportSource | None:
    with Session(engine) as session:
        return session.exec(select(ImportSource).where(ImportSource.url == url)).first()


def delete_source(source_id: int) -> bool:
    """Удалить источник, все его сервера и назначения юзерам."""
    with Session(engine) as session:
        src = session.get(ImportSource, source_id)
        if src is None:
            return False
        for s in session.exec(
            select(ExtraServer).where(ExtraServer.source_id == source_id)
        ).all():
            session.delete(s)
        for us in session.exec(
            select(UserSource).where(UserSource.source_id == source_id)
        ).all():
            session.delete(us)
        session.delete(src)
        session.commit()
        return True


def list_user_sources(user_token: str) -> list[int]:
    with Session(engine) as session:
        return list(
            session.exec(
                select(UserSource.source_id).where(UserSource.user_token == user_token)
            ).all()
        )


def set_user_sources(user_token: str, source_ids: list[int]) -> list[int]:
    """Полностью заменить набор назначенных юзеру источников."""
    wanted = set(source_ids)
    with Session(engine) as session:
        current = session.exec(
            select(UserSource).where(UserSource.user_token == user_token)
        ).all()
        have = {x.source_id for x in current}
        for x in current:
            if x.source_id not in wanted:
                session.delete(x)
        for sid in wanted - have:
            session.add(UserSource(user_token=user_token, source_id=sid))
        session.commit()
    return sorted(wanted)


def reconcile_source(source_id: int, items: list[dict]) -> dict:
    """Синхронизировать сервера источника со свежим списком.

    items: [{"link":..., "ckey":..., "name":...}]
    Возвращает {added, updated, removed}. Сохраняет enabled/is_global/
    назначения у существующих (матчинг по ckey).
    """
    wanted = {it["ckey"]: it for it in items}
    added = updated = removed = 0
    with Session(engine) as session:
        src = session.get(ImportSource, source_id)
        existing = session.exec(
            select(ExtraServer).where(ExtraServer.source_id == source_id)
        ).all()
        have = {}
        for s in existing:
            # дубликаты по ключу схлопываем (оставляем первый)
            if s.ckey in have:
                session.delete(s)
                removed += 1
                continue
            have[s.ckey] = s

        # удалить исчезнувшие
        for key, s in have.items():
            if key not in wanted:
                session.delete(s)
                removed += 1

        # добавить/обновить
        for key, it in wanted.items():
            s = have.get(key)
            if s is None:
                session.add(
                    ExtraServer(
                        link=it["link"], name=it["name"], enabled=True,
                        is_global=(src.is_global if src else True),
                        source_id=source_id, ckey=key,
                        position=_next_position(session),
                    )
                )
                added += 1
            else:
                if s.link != it["link"] or s.name != it["name"]:
                    s.link = it["link"]
                    s.name = it["name"]
                    session.add(s)
                    updated += 1

        if src is not None:
            src.last_synced = datetime.utcnow()
            src.last_count = len(wanted)
            session.add(src)
        session.commit()
    return {"added": added, "updated": updated, "removed": removed}


def touch_subscription(token: str, title: str | None = None) -> None:
    """Зафиксировать, что токен проходил через менеджер (опц. с названием)."""
    with Session(engine) as session:
        sub = session.get(Subscription, token)
        now = datetime.utcnow()
        if sub is None:
            session.add(Subscription(token=token, title=title, created_at=now, last_seen=now))
        else:
            sub.last_seen = now
            if title is not None:
                sub.title = title
            session.add(sub)
        session.commit()
