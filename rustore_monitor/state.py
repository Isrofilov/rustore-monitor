"""Хранение состояния в SQLite."""

import sqlite3

from . import config


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
    return conn


def load_comment_ids(conn: sqlite3.Connection) -> set[int]:
    return {row[0] for row in conn.execute("SELECT comment_id FROM reviews")}


def load_edited_ids(conn: sqlite3.Connection) -> set[int]:
    return {row[0] for row in conn.execute("SELECT comment_id FROM reviews WHERE edited = 1")}


def load_ratings(conn: sqlite3.Connection) -> dict[str, int]:
    return {row[0]: row[1] for row in conn.execute("SELECT key, value FROM ratings")}


def load_invoice_ids(conn: sqlite3.Connection, today: str) -> set[int]:
    return {row[0] for row in conn.execute(
        "SELECT invoice_id FROM invoices WHERE invoice_date = ?", (today,)
    )}


def has_invoice_date(conn: sqlite3.Connection, today: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM invoices WHERE invoice_date = ? LIMIT 1", (today,)
    ).fetchone()
    return row is not None


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def save_reviews(conn: sqlite3.Connection, comment_ids: set[int], edited_ids: set[int]):
    conn.execute("DELETE FROM reviews")
    conn.executemany(
        "INSERT INTO reviews (comment_id, edited) VALUES (?, ?)",
        [(cid, 1 if cid in edited_ids else 0) for cid in comment_ids],
    )


def save_invoices(conn: sqlite3.Connection, invoice_ids: set[int], today: str):
    conn.executemany(
        "INSERT OR IGNORE INTO invoices (invoice_id, invoice_date) VALUES (?, ?)",
        [(iid, today) for iid in invoice_ids],
    )


def save_ratings(conn: sqlite3.Connection, ratings: dict):
    conn.execute("DELETE FROM ratings")
    conn.executemany(
        "INSERT INTO ratings (key, value) VALUES (?, ?)",
        list(ratings.items()),
    )


def save_meta(conn: sqlite3.Connection, **kwargs):
    conn.executemany(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
        list(kwargs.items()),
    )
