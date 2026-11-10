"""The local SQLite log. Only redacted command text and its rating are ever stored."""
import os
import pathlib
import sqlite3
import time

from .classify import classify
from .redact import redact

DEFAULT_RETENTION_DAYS = 90
SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    session TEXT NOT NULL,
    turn INTEGER NOT NULL,
    cwd TEXT NOT NULL,
    command TEXT NOT NULL,
    categories TEXT NOT NULL,
    rating TEXT NOT NULL,
    rule TEXT NOT NULL,
    why TEXT NOT NULL,
    destinations TEXT NOT NULL,
    failed INTEGER NOT NULL,
    acked_at INTEGER
);
CREATE TABLE IF NOT EXISTS turns (session TEXT PRIMARY KEY, turn INTEGER NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def home():
    return pathlib.Path(os.environ.get("SIDELEDGER_HOME") or pathlib.Path.home() / ".sideledger")


def connect():
    folder = home()
    os.makedirs(folder, mode=0o700, exist_ok=True)
    path = folder / "ledger.db"
    os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def retention_days(conn):
    row = conn.execute("SELECT value FROM settings WHERE key = 'retention_days'").fetchone()
    return int(row["value"]) if row else DEFAULT_RETENTION_DAYS


def set_retention_days(conn, days):
    if days < 1:
        raise ValueError("retention must be at least 1 day")
    with conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('retention_days', ?)", (str(days),))


def next_turn(conn, session, now=None):
    now = int(time.time() if now is None else now)
    with conn:
        conn.execute("INSERT INTO turns (session, turn, ts) VALUES (?, 1, ?) "
                     "ON CONFLICT (session) DO UPDATE SET turn = turn + 1, ts = excluded.ts", (session, now))


def record(conn, session, cwd, command, failed, now=None):
    """Rate the raw text in memory, then store only the redacted text."""
    now = int(time.time() if now is None else now)
    # cwd is Claude Code's folder AFTER the command ran (checked live 2026-11-10), so a leading
    # `cd X &&` is already in it. ponytail: `rm a && cd b` is filed under b; a PreToolUse hook
    # would give the folder before, add it if that case matters.
    rated = classify(command, cwd)
    cutoff = now - retention_days(conn) * 86400
    with conn:
        conn.execute("INSERT OR IGNORE INTO turns (session, turn, ts) VALUES (?, 1, ?)", (session, now))
        turn = conn.execute("SELECT turn FROM turns WHERE session = ?", (session,)).fetchone()["turn"]
        conn.execute(
            "INSERT INTO actions (ts, session, turn, cwd, command, categories, rating, rule, why, destinations, failed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now, session, turn, cwd, redact(command), ",".join(rated["categories"]), rated["rating"], rated["rule"],
             rated["why"], ", ".join(redact(d) for d in rated["destinations"]), int(failed)),
        )
        # An unreviewed irreversible action never ages out: check would then pass without anyone looking.
        conn.execute("DELETE FROM actions WHERE ts < ? AND NOT (rating = 'irreversible' AND acked_at IS NULL)", (cutoff,))
        conn.execute("DELETE FROM turns WHERE ts < ? AND session != ?", (cutoff, session))


def actions(conn, session, turn=None):
    if turn is None:
        return conn.execute("SELECT * FROM actions WHERE session = ? ORDER BY id", (session,)).fetchall()
    return conn.execute("SELECT * FROM actions WHERE session = ? AND turn = ? ORDER BY id", (session, turn)).fetchall()


def _in_folder(cwd, root):
    return cwd == root or cwd.startswith(root.rstrip("/") + "/")


def latest_session(conn, root=None):
    for row in conn.execute("SELECT session, cwd FROM actions ORDER BY id DESC"):
        if root is None or _in_folder(row["cwd"], root):
            return row["session"]
    return None


def latest_turn(conn, session):
    return conn.execute("SELECT MAX(turn) AS turn FROM actions WHERE session = ?", (session,)).fetchone()["turn"]


def unreviewed(conn, root=None, rating="irreversible"):
    rows = conn.execute("SELECT * FROM actions WHERE rating = ? AND acked_at IS NULL ORDER BY id", (rating,)).fetchall()
    if root is None:
        return rows
    return [r for r in rows if _in_folder(r["cwd"], root)]


def ack(conn, ids, now=None):
    now = int(time.time() if now is None else now)
    marks = ",".join("?" * len(ids))
    with conn:
        cursor = conn.execute(f"UPDATE actions SET acked_at = ? WHERE acked_at IS NULL AND id IN ({marks})", (now, *ids))
    return cursor.rowcount
