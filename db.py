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
    """

    id: int | None = Field(default=None, primary_key=True)
    link: str
    name: str | None = None
    enabled: bool = True
    is_global: bool = True


class UserAssignment(SQLModel, table=True):
    """Связка: какой персональный сервер назначен какому юзеру (по токену)."""

    id: int | None = Field(default=None, primary_key=True)
    user_token: str = Field(index=True)
    server_id: int = Field(index=True)


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
    """Лёгкая миграция: добавить is_global в старые таблицы extraserver."""
    insp = inspect(engine)
    if "extraserver" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("extraserver")}
    if "is_global" not in cols:
        default = "1" if config.DB_URL.startswith("sqlite") else "true"
        with engine.begin() as conn:
            conn.execute(
                text(f"ALTER TABLE extraserver ADD COLUMN is_global BOOLEAN DEFAULT {default}")
            )


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
            )
        ).all()
        return [r.link for r in rows]


def get_links_for_token(user_token: str) -> list[str]:
    """Ссылки для конкретной подписки: глобальные + персонально назначенные."""
    with Session(engine) as session:
        global_rows = session.exec(
            select(ExtraServer).where(
                ExtraServer.enabled == True, ExtraServer.is_global == True  # noqa: E712
            )
        ).all()
        assigned_ids = session.exec(
            select(UserAssignment.server_id).where(UserAssignment.user_token == user_token)
        ).all()
        links = [r.link for r in global_rows]
        if assigned_ids:
            personal = session.exec(
                select(ExtraServer).where(
                    ExtraServer.id.in_(assigned_ids),  # type: ignore[attr-defined]
                    ExtraServer.enabled == True,  # noqa: E712
                    ExtraServer.is_global == False,  # noqa: E712
                )
            ).all()
            links += [r.link for r in personal]
        return links


def list_servers() -> list[ExtraServer]:
    with Session(engine) as session:
        return list(session.exec(select(ExtraServer).order_by(ExtraServer.id)).all())


def get_server(server_id: int) -> ExtraServer | None:
    with Session(engine) as session:
        return session.get(ExtraServer, server_id)


def add_server(
    link: str, name: str | None = None, enabled: bool = True, is_global: bool = True
) -> ExtraServer:
    with Session(engine) as session:
        server = ExtraServer(link=link, name=name, enabled=enabled, is_global=is_global)
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


def touch_subscription(token: str) -> None:
    """Зафиксировать, что токен проходил через менеджер."""
    with Session(engine) as session:
        sub = session.get(Subscription, token)
        now = datetime.utcnow()
        if sub is None:
            session.add(Subscription(token=token, created_at=now, last_seen=now))
        else:
            sub.last_seen = now
            session.add(sub)
        session.commit()
