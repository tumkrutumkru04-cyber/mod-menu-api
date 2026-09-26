import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = os.getenv("DATABASE_PATH", "/data/keys.db")
DEFAULT_CLAIM_HOURS = float(os.getenv("DEFAULT_CLAIM_HOURS", "24"))
MAX_HOURS = float(os.getenv("MAX_HOURS", "8760"))


def utc_now():
    return datetime.now(timezone.utc)


def iso_time(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def db():
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_value TEXT NOT NULL UNIQUE,
                prefix TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                max_devices INTEGER NOT NULL DEFAULT 1,
                revoked INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER NOT NULL,
                device_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(key_id, device_hash),
                FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE CASCADE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_value ON keys(key_value)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_key ON devices(key_id)")


def json_error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def device_hash(device_id):
    return hashlib.sha256(device_id.strip().encode("utf-8")).hexdigest()


def key_string(prefix):
    clean = "".join(c for c in prefix.upper() if c.isalnum() or c == "-")[:18] or "HEX-CHATS"
    return f"{clean}-{secrets.token_hex(5).upper()}"


def get_key(conn, value):
    return conn.execute("SELECT * FROM keys WHERE key_value = ?", (value,)).fetchone()


def key_response(conn, row, include_devices=False):
    used = conn.execute("SELECT COUNT(*) AS n FROM devices WHERE key_id = ?", (row["id"],)).fetchone()["n"]
    data = {
        "ok": True,
        "key": row["key_value"],
        "validity": f"{max(0, (datetime.fromisoformat(row['expires_at']) - datetime.fromisoformat(row['created_at'])).total_seconds() / 3600):g} Hours",
        "expires_at": iso_time(datetime.fromisoformat(row["expires_at"])),
        "max_devices": row["max_devices"],
        "used_devices": used,
        "revoked": bool(row["revoked"]),
    }
    if include_devices:
        data["devices"] = [
            {"first_seen": iso_time(datetime.fromisoformat(x["first_seen"])),
             "last_seen": iso_time(datetime.fromisoformat(x["last_seen"]))}
            for x in conn.execute("SELECT first_seen,last_seen FROM devices WHERE key_id = ?", (row["id"],))
        ]
    return data


def create_key(hours, max_devices, prefix):
    if hours <= 0 or hours > MAX_HOURS:
        raise ValueError(f"hours must be between 0 and {MAX_HOURS}")
    if max_devices < 1 or max_devices > 10000:
        raise ValueError("max_devices must be between 1 and 10000")
    now = utc_now()
    expires = now + timedelta(hours=hours)
    with db() as conn:
        for _ in range(10):
            value = key_string(prefix)
            try:
                conn.execute("INSERT INTO keys(key_value,prefix,created_at,expires_at,max_devices) VALUES(?,?,?,?,?)",
                             (value, prefix, now.isoformat(), expires.isoformat(), max_devices))
                row = get_key(conn, value)
                return key_response(conn, row)
            except sqlite3.IntegrityError:
                continue
    raise RuntimeError("Could not generate a unique key")


@app.get("/")
def home():
    return jsonify({"ok": True, "service": "key-api", "version": "1.0.0"})


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "key-api"})


@app.post("/api/v1/keys/claim")
def claim_key():
    body = request.get_json(silent=True) or {}
    try:
        hours = float(body.get("hours", DEFAULT_CLAIM_HOURS))
        max_devices = int(body.get("max_devices", 1))
        prefix = str(body.get("prefix", "HEX-CHATS"))
        return jsonify(create_key(hours, max_devices, prefix)), 201
    except (TypeError, ValueError) as exc:
        return json_error(str(exc))


@app.post("/api/v1/keys/create")
def create_key_admin():
    body = request.get_json(silent=True) or {}
    try:
        if "hours" not in body and "days" not in body:
            return json_error("Provide hours or days")
        hours = float(body.get("hours", 0)) if "hours" in body else float(body["days"]) * 24
        max_devices = int(body.get("max_devices", 1))
        prefix = str(body.get("prefix", "HEX-CHATS"))
        return jsonify(create_key(hours, max_devices, prefix)), 201
    except (TypeError, ValueError) as exc:
        return json_error(str(exc))


@app.post("/api/v1/keys/validate")
def validate_key():
    body = request.get_json(silent=True) or {}
    value = str(body.get("key", "")).strip()
    device_id = str(body.get("device_id", "")).strip()
    if not value or not device_id:
        return json_error("key and device_id are required")
    now = utc_now()
    with db() as conn:
        row = get_key(conn, value)
        if not row:
            return json_error("Invalid key", 401)
        expires = datetime.fromisoformat(row["expires_at"])
        if row["revoked"]:
            return json_error("Key revoked", 403)
        if now > expires:
            return jsonify({"ok": False, "error": "Key expired", "expires_at": iso_time(expires)}), 403
        digest = device_hash(device_id)
        existing = conn.execute("SELECT id FROM devices WHERE key_id = ? AND device_hash = ?", (row["id"], digest)).fetchone()
        if not existing:
            used = conn.execute("SELECT COUNT(*) AS n FROM devices WHERE key_id = ?", (row["id"],)).fetchone()["n"]
            if used >= row["max_devices"]:
                return json_error("Device limit reached", 403)
            conn.execute("INSERT INTO devices(key_id,device_hash,first_seen,last_seen) VALUES(?,?,?,?)",
                         (row["id"], digest, now.isoformat(), now.isoformat()))
        else:
            conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now.isoformat(), existing["id"]))
        result = key_response(conn, row)
        result.update({"message": "Key valid", "device_bound": True, "expires_at": iso_time(expires)})
        return jsonify(result)


@app.get("/api/v1/keys/<value>")
def inspect_key(value):
    with db() as conn:
        row = get_key(conn, value)
        if not row:
            return json_error("Key not found", 404)
        return jsonify(key_response(conn, row, include_devices=True))


@app.post("/api/v1/keys/revoke")
def revoke_key():
    body = request.get_json(silent=True) or {}
    value = str(body.get("key", "")).strip()
    if not value:
        return json_error("key is required")
    with db() as conn:
        changed = conn.execute("UPDATE keys SET revoked = 1 WHERE key_value = ?", (value,)).rowcount
        if not changed:
            return json_error("Key not found", 404)
    return jsonify({"ok": True, "key": value, "revoked": True})


@app.errorhandler(404)
def not_found(_):
    return json_error("Not found", 404)


@app.errorhandler(500)
def server_error(_):
    return json_error("Internal server error", 500)


init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
