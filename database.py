import hashlib
import secrets
import sqlite3
import time
from contextlib import closing
from typing import Optional, Tuple

from config import DB_PATH, ADMIN_PASSWORD, ADMIN_USERNAME


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with closing(get_connection()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                telegram_user_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS admin_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_id TEXT,
                file_path TEXT,
                uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS found_passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                password TEXT NOT NULL,
                source_file TEXT,
                found_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                blocked_until REAL
            );
            
            CREATE TABLE IF NOT EXISTS running_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                pid INTEGER NOT NULL,
                hc22000_path TEXT,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
            );
            """
        )
        conn.commit()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()
    return f"{salt}:{digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, digest = stored_hash.split(":", 1)
    except ValueError:
        return False
    computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()
    return secrets.compare_digest(computed, digest)


def ensure_default_admin() -> None:
    with closing(get_connection()) as conn:
        existing = conn.execute("SELECT id FROM admins WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
        if existing:
            return

        password = ADMIN_PASSWORD.strip() if ADMIN_PASSWORD else ""
        if not password:
            return

        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (ADMIN_USERNAME, hash_password(password)),
        )
        conn.commit()


def create_admin(username: str, password: str) -> Tuple[bool, str]:
    if not username or not password:
        return False, "Username and password are required"
    with closing(get_connection()) as conn:
        exists = conn.execute("SELECT id FROM admins WHERE username = ?", (username,)).fetchone()
        if exists:
            return False, "An admin with this username already exists"
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        conn.commit()
    return True, "Admin created"


def get_admin_by_username(username: str) -> Optional[sqlite3.Row]:
    with closing(get_connection()) as conn:
        return conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()


def authenticate_admin(username: str, password: str, telegram_user_id: int) -> Tuple[bool, str]:
    admin = get_admin_by_username(username)
    if not admin:
        return False, "User not found"

    now = time.time()
    with closing(get_connection()) as conn:
        attempt_row = conn.execute(
            "SELECT attempt_count, blocked_until FROM login_attempts WHERE username = ?",
            (username,),
        ).fetchone()

        if attempt_row:
            if attempt_row["blocked_until"] and now < attempt_row["blocked_until"]:
                remaining = int(attempt_row["blocked_until"] - now)
                return False, f"The account is blocked for {remaining} seconds"

        if verify_password(password, admin["password_hash"]):
            conn.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
            conn.execute(
                "UPDATE admins SET telegram_user_id = ? WHERE id = ?",
                (telegram_user_id, admin["id"]),
            )
            conn.commit()
            return True, "Authentication successful"

        if attempt_row is None:
            conn.execute(
                "INSERT INTO login_attempts (username, attempt_count, blocked_until) VALUES (?, 0, NULL)",
                (username,),
            )
            attempt_row = {"attempt_count": 0, "blocked_until": None}

        new_count = attempt_row["attempt_count"] + 1
        if new_count <= 3:
            blocked_until = now + 60
        elif new_count <= 6:
            blocked_until = now + 10 * 3600
        else:
            blocked_until = now + 365 * 24 * 3600
        conn.execute(
            "UPDATE login_attempts SET attempt_count = ?, blocked_until = ? WHERE username = ?",
            (new_count, blocked_until, username),
        )
        conn.commit()
        return False, "Incorrect password"


def is_authorized(telegram_user_id: int) -> bool:
    with closing(get_connection()) as conn:
        row = conn.execute("SELECT id FROM admins WHERE telegram_user_id = ?", (telegram_user_id,)).fetchone()
        return row is not None


def clear_authorization(telegram_user_id: int) -> None:
    with closing(get_connection()) as conn:
        conn.execute("UPDATE admins SET telegram_user_id = NULL WHERE telegram_user_id = ?", (telegram_user_id,))
        conn.commit()


def record_admin_file(admin_id: int, filename: str, file_id: Optional[str], file_path: str) -> None:
    with closing(get_connection()) as conn:
        conn.execute(
            "INSERT INTO admin_files (admin_id, filename, file_id, file_path) VALUES (?, ?, ?, ?)",
            (admin_id, filename, file_id, file_path),
        )
        conn.commit()


    def record_current_process(admin_id: int, pid: int, hc22000_path: str) -> None:
        with closing(get_connection()) as conn:
            conn.execute(
                "INSERT INTO running_processes (admin_id, pid, hc22000_path) VALUES (?, ?, ?)",
                (admin_id, pid, hc22000_path),
            )
            conn.commit()


    def get_current_process(admin_id: int):
        with closing(get_connection()) as conn:
            return conn.execute(
                "SELECT id, pid, hc22000_path, started_at FROM running_processes WHERE admin_id = ? ORDER BY id DESC LIMIT 1",
                (admin_id,),
            ).fetchone()


    def clear_current_process(admin_id: int) -> None:
        with closing(get_connection()) as conn:
            conn.execute("DELETE FROM running_processes WHERE admin_id = ?", (admin_id,))
            conn.commit()


def record_found_password(admin_id: int, password: str, source_file: str) -> None:
    stored_password = hash_password(password)
    with closing(get_connection()) as conn:
        conn.execute(
            "INSERT INTO found_passwords (admin_id, password, source_file) VALUES (?, ?, ?)",
            (admin_id, stored_password, source_file),
        )
        conn.commit()


def get_admin_files(admin_id: int):
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT filename, uploaded_at FROM admin_files WHERE admin_id = ? ORDER BY id DESC LIMIT 10",
            (admin_id,),
        ).fetchall()


def get_found_passwords(admin_id: int):
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT password, source_file, found_at FROM found_passwords WHERE admin_id = ? ORDER BY id DESC LIMIT 10",
            (admin_id,),
        ).fetchall()
