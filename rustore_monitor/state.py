"""Хранение состояния в SQLite."""

import sqlite3

from . import config


def _add_column(conn: sqlite3.Connection, table: str, column: str, decl: str):
    """Добавляет колонку в существующую таблицу, если её ещё нет (миграция старых БД)."""
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def get_db() -> sqlite3.Connection:
    """Возвращает соединение с БД, создаёт таблицы при первом вызове."""
    config.DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_FILE))
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
    """)
    # оценка и текст отзыва — чтобы ловить повторные правки и показывать «было → стало».
    # У строк из старой схемы они NULL: такие отзывы просто заполняются без уведомления.
    _add_column(conn, "reviews", "rating", "INTEGER")
    _add_column(conn, "reviews", "text", "TEXT")
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


def load_invoice_ids(conn: sqlite3.Connection, today: str) -> set[int]:
    return {row[0] for row in conn.execute(
        "SELECT invoice_id FROM invoices WHERE invoice_date = ?", (today,)
    )}


def save_invoices(conn: sqlite3.Connection, invoice_ids: set[int], today: str):
    conn.executemany(
        "INSERT OR IGNORE INTO invoices (invoice_id, invoice_date) VALUES (?, ?)",
        [(iid, today) for iid in invoice_ids],
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
