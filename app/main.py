import sqlite3
import os
import logging
import hashlib
import datetime

import jwt
from flask import Flask, request, jsonify, g
from functools import wraps

app = Flask(__name__)

# [VULN] CWE-798: секрет захардкожен в коде
SECRET_KEY = "supersecret123"
DB_PATH = "oil_gas_vuln.db"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS equipment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            status TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS work_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipment_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            created_by INTEGER NOT NULL,
            assigned_to INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            entity TEXT,
            entity_id INTEGER,
            detail TEXT,
            ts TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # [VULN] CWE-916: MD5 без соли
    users = [
        ("admin",     hashlib.md5("admin123".encode()).hexdigest(),  "admin"),
        ("engineer1", hashlib.md5("engineer1".encode()).hexdigest(), "engineer"),
        ("operator1", hashlib.md5("operator1".encode()).hexdigest(), "operator"),
    ]
    for username, password_hash, role in users:
        exists = cur.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        if not exists:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, password_hash, role)
            )

    for name, loc in [("Pump-01","Section A"),("Valve-03","Section B"),("Compressor-07","Section C")]:
        exists = cur.execute(
            "SELECT 1 FROM equipment WHERE name=?", (name,)
        ).fetchone()
        if not exists:
            cur.execute(
                "INSERT INTO equipment (name, location) VALUES (?,?)", (name, loc)
            )

    conn.commit()
    conn.close()

def create_token(user_id, username, role):
    payload = {
        "id": user_id,
        "username": username,
        "role": role,
        # [VULN] CWE-916: нет срока жизни токена
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token):
    try:
        # [VULN] нет проверки exp
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        user = decode_token(token)
        if not user:
            return jsonify({"error": "Invalid token"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # [VULN] CWE-916: MD5 без соли
    hashed = hashlib.md5(password.encode()).hexdigest()

    # [VULN] CWE-89: f-string в SQL запросе
    db = get_db()
    cur = db.execute(
        f"SELECT * FROM users WHERE username='{username}' AND password_hash='{hashed}'"
    )
    row = cur.fetchone()

    if not row:
        # [VULN] CWE-532: пароль в логах
        logger.info(f"Failed login for user: {username}, password tried: {password}")
        # [VULN] CWE-209: раскрытие информации
        return jsonify({"error": f"User {username} not found or wrong password"}), 401

    token = create_token(row["id"], row["username"], row["role"])
    logger.info(f"User logged in: {username}")
    return jsonify({"token": token, "role": row["role"]})

# [VULN] CWE-306: нет @require_auth
@app.route("/equipment", methods=["GET"])
def list_equipment():
    db = get_db()
    rows = db.execute("SELECT * FROM equipment").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/equipment", methods=["POST"])
@require_auth
def add_equipment():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "")
    location = data.get("location", "")

    db = get_db()
    # [VULN] CWE-89: f-string в SQL
    cur = db.execute(
        f"INSERT INTO equipment (name, location) VALUES ('{name}', '{location}')"
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "name": name}), 201

# [VULN] CWE-306: нет @require_auth
@app.route("/work-orders", methods=["GET"])
def list_work_orders():
    db = get_db()
    rows = db.execute("SELECT * FROM work_orders").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/work-orders", methods=["POST"])
@require_auth
def create_work_order():
    data = request.get_json(silent=True) or {}
    equipment_id = data.get("equipment_id")
    description = data.get("description", "")

    db = get_db()
    cur = db.execute(
        "INSERT INTO work_orders (equipment_id, description, created_by) VALUES (?,?,?)",
        (equipment_id, description, g.current_user["id"])
    )
    db.commit()
    return jsonify({"id": cur.lastrowid}), 201


@app.route("/work-orders/<int:order_id>/status", methods=["PATCH"])
@require_auth
def update_status(order_id):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "")

    db = get_db()
    order = db.execute(
        "SELECT * FROM work_orders WHERE id=?", (order_id,)
    ).fetchone()
    if not order:
        return jsonify({"error": "Work order not found"}), 404

    # [VULN] CWE-285: нет проверки роли и assigned_to
    db.execute(
        "UPDATE work_orders SET status=? WHERE id=?", (new_status, order_id)
    )
    db.commit()
    return jsonify({"updated": True, "status": new_status})


@app.route("/work-orders/<int:order_id>/close", methods=["POST"])
@require_auth
def close_work_order(order_id):
    db = get_db()
    order = db.execute(
        "SELECT * FROM work_orders WHERE id=?", (order_id,)
    ).fetchone()
    if not order:
        return jsonify({"error": "Work order not found"}), 404

    # [VULN] CWE-285: нет проверки роли и assigned_to
    db.execute(
        "UPDATE work_orders SET status='closed' WHERE id=?", (order_id,)
    )
    db.commit()
    return jsonify({"closed": True})


# [VULN] CWE-285: нет проверки роли — любой может получить отчёт
@app.route("/report", methods=["GET"])
@require_auth
def export_report():
    db = get_db()
    rows = db.execute("SELECT * FROM work_orders").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    # [VULN] CWE-489: debug=True, host=0.0.0.0
    app.run(debug=True, host="0.0.0.0", port=5003)