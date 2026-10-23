"""Хранение состояния в SQLite."""

import os
import logging
import sqlite3

from . import config

log = logging.getLogger(__name__)


def _add_column(conn: sqlite3.Connection, table: str, column: str, decl: str):
    """Добавляет колонку в существующую таблицу, если её ещё нет (миграция старых БД)."""
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def migrate_legacy_db():
    """Переносит базу из версий с одним приложением (state.db) в файл приложения.

    Старая база принадлежит приложению из RUSTORE_PACKAGE_NAME, а если оно не
    задано — единственному приложению в RUSTORE_APPS.
    """
    legacy = config.LEGACY_DB_FILE
    if not legacy.exists():
        return
    owner = os.environ.get("RUSTORE_PACKAGE_NAME")
    if not owner and len(config.APPS) == 1:
        owner = config.APPS[0].package
    app = next((a for a in config.APPS if a.package == owner), None)
    if app is None or app.db_file.exists():
        log.warning("Найдена старая база %s, но непонятно, к какому приложению она относится — пропускаю", legacy)
        return
    for suffix in ("", "-wal", "-shm"):
        src = legacy.with_name(legacy.name + suffix)
        if src.exists():
            src.rename(app.db_file.with_name(app.db_file.name + suffix))
    log.info("База %s перенесена в %s", legacy, app.db_file)


def get_db(app: config.App) -> sqlite3.Connection:
    """Возвращает соединение с БД приложения, создаёт таблицы при первом вызове."""
    app.db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(app.db_file))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS reviews (
            comment_id INTEGER PRIMARY KEY,
            edited     INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS invoices (
            invoice_id   INTEGER PRIMARY KEY,
            invoice_date TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ratings (
            key   TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS versions (
            version_id INTEGER PRIMARY KEY,
            status     TEXT NOT NULL,
            partial    INTEGER
        );
        CREATE TABLE IF NOT EXISTS developers (
            vk_id TEXT NOT NULL,
            role  TEXT NOT NULL,
            name  TEXT,
            PRIMARY KEY (vk_id, role)
        );
    """)
    # оценка и текст отзыва — чтобы ловить повторные правки и показывать «было → стало».
    # У строк из старой схемы они NULL: такие отзывы просто заполняются без уведомления.
    _add_column(conn, "reviews", "rating", "INTEGER")
    _add_column(conn, "reviews", "text", "TEXT")
    # раньше хранились только подтверждённые платежи
    _add_column(conn, "invoices", "status", "TEXT NOT NULL DEFAULT 'CONFIRMED'")
    conn.commit()
    return conn


# ── отзывы и оценки ──


def load_reviews(conn: sqlite3.Connection) -> dict[int, tuple[int | None, str | None]]:
    """commentId → (оценка, текст)."""
    return {
        row[0]: (row[1], row[2])
        for row in conn.execute("SELECT comment_id, rating, text FROM reviews")
    }


def load_ratings(conn: sqlite3.Connection) -> dict[str, int]:
    return {row[0]: row[1] for row in conn.execute("SELECT key, value FROM ratings")}


def save_reviews(conn: sqlite3.Connection, reviews: list[dict]):
    conn.execute("DELETE FROM reviews")
    conn.executemany(
        "INSERT OR REPLACE INTO reviews (comment_id, edited, rating, text) VALUES (?, ?, ?, ?)",
        [
            (r["commentId"], 1 if r.get("edited") else 0, r["appRating"], r.get("commentText") or "")
            for r in reviews
        ],
    )


def save_ratings(conn: sqlite3.Connection, ratings: dict):
    conn.execute("DELETE FROM ratings")
    conn.executemany(
        "INSERT INTO ratings (key, value) VALUES (?, ?)",
        list(ratings.items()),
    )


# ── платежи ──


def load_invoice_statuses(conn: sqlite3.Connection) -> dict[int, str]:
    """invoiceId → последний известный статус (в верхнем регистре)."""
    return {row[0]: row[1] for row in conn.execute("SELECT invoice_id, status FROM invoices")}


def save_invoices(conn: sqlite3.Connection, invoices: list[tuple[int, str, str]]):
    """Сохраняет платежи как (invoiceId, дата запроса, статус)."""
    conn.executemany(
        "INSERT OR REPLACE INTO invoices (invoice_id, invoice_date, status) VALUES (?, ?, ?)",
        invoices,
    )


def delete_invoices_before(conn: sqlite3.Connection, date: str):
    """Удаляет платежи, вышедшие за окно проверки."""
    conn.execute("DELETE FROM invoices WHERE invoice_date < ?", (date,))


# ── версии ──


def load_versions(conn: sqlite3.Connection) -> dict[int, tuple[str, int | None]]:
    """versionId → (статус, % частичной публикации)."""
    return {
        row[0]: (row[1], row[2])
        for row in conn.execute("SELECT version_id, status, partial FROM versions")
    }


def save_versions(conn: sqlite3.Connection, versions: list[dict]):
    conn.executemany(
        "INSERT OR REPLACE INTO versions (version_id, status, partial) VALUES (?, ?, ?)",
        [(v["versionId"], v["versionStatus"], v.get("partialValue")) for v in versions],
    )


# ── доступы ──


def load_developers(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    """(vkId, роль) → имя пользователя."""
    return {
        (row[0], row[1]): row[2]
        for row in conn.execute("SELECT vk_id, role, name FROM developers")
    }


def save_developers(conn: sqlite3.Connection, developers: dict[tuple[str, str], str]):
    conn.execute("DELETE FROM developers")
    conn.executemany(
        "INSERT INTO developers (vk_id, role, name) VALUES (?, ?, ?)",
        [(vk_id, role, name) for (vk_id, role), name in developers.items()],
    )


# ── meta ──


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def save_meta(conn: sqlite3.Connection, **kwargs):
    conn.executemany(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
        list(kwargs.items()),
    )
