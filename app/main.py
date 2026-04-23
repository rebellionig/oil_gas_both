import sqlite3
import os
import logging
import datetime

import bcrypt
import jwt
import csv
import io

from flask import Flask, request, jsonify, g, Response
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

#1. нововведения (1-x) которые будут добавлены в p5
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

MAX_ROWS = 200
MAX_PASSWORD_LEN = 128

#.1 окончания добавления нововведения 1 в p5

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY not set")

DB_PATH = os.environ.get("DB_PATH", "oil_gas.db")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

#2
@app.errorhandler(413)
def request_too_large(e):
    logger.warning("Request body too large from %s", request.remote_addr)
    return jsonify({"error": "Request body too large"}), 413
#2

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
    with sqlite3.connect(DB_PATH) as conn:
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
    conn.commit()
    # Начальные пользователи
    users = [
        ("admin", "admin123", "admin"),
        ("engineer1", "engineer1", "engineer"),
        ("operator1", "operator1", "operator"),
    ]
    for username, password, role in users:
        exists = cur.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        if not exists:
            hashed = bcrypt.hashpw(
                password.encode(), bcrypt.gensalt()
            ).decode()
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, hashed, role)
            )

    # Начальное оборудование
    equipment = [
        ("Pump-01", "Section A"),
        ("Valve-03", "Section B"),
        ("Compressor-07", "Section C"),
    ]
    for name, location in equipment:
        exists = cur.execute(
            "SELECT 1 FROM equipment WHERE name=?", (name,)
        ).fetchone()
        if not exists:
            cur.execute(
                "INSERT INTO equipment (name, location) VALUES (?,?)",
                (name, location)
            )

    conn.commit()
    
    
def audit(action, entity=None, entity_id=None, detail=None, user_id=None):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, action, entity, entity_id, detail)"
            " VALUES (?,?,?,?,?)",
            (user_id, action, entity, entity_id, detail)
        )
        db.commit()
    except sqlite3.Error as e:
        logger.error("audit error (sqlite): %s", e)
    except Exception as e:
        logger.error("audit error (unexpected): %s", type(e).__name__)

def create_token(user_id, username, role):
    payload = {
        "id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        user = decode_token(token)
        if not user:
            return jsonify({"error": "Invalid or expired token"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.current_user.get("role") not in roles:
                logger.warning(
                    "Access denied: user=%s role=%s path=%s",
                    g.current_user.get("username"),
                    g.current_user.get("role"),
                    request.path
                )
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

def check_object_access(order, action="modify"):
    user = g.current_user
    if user["role"] == "admin":
        return True, None
    if user["role"] == "engineer":
        if order["assigned_to"] != user["id"]:
            logger.warning(
                "Object access denied: user=%s tried to %s order=%s",
                user["username"], action, order["id"]
            )
            audit(
                "OBJECT_ACCESS_DENIED",
                "work_order", order["id"],
                detail=f"action={action}",
                user_id=user["id"]
            )
            return False, (jsonify({"error": "Forbidden: not assigned to you"}), 403)
    return True, None

def validate_text(value, field_name, max_len=255):
    if not value or not isinstance(value, str):
        return None, f"{field_name} is required"
    value = value.strip()
    if len(value) == 0:
        return None, f"{field_name} cannot be empty"
    if len(value) > max_len:
        return None, f"{field_name} too long (max {max_len})"
    return value, None


def validate_int(value, field_name):
    try:
        v = int(value)
        if v <= 0:
            raise ValueError
        return v, None
    except (TypeError, ValueError):
        return None, f"{field_name} must be a positive integer"
    
@app.route("/login", methods=["POST"])

def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()[:64]
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"error": "Invalid credentials"}), 401

    if len(password) > MAX_PASSWORD_LEN:
        return jsonify({"error": "Invalid credentials"}), 401

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not row or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        logger.warning("Failed login: %s", username)
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(row["id"], row["username"], row["role"])
    audit("LOGIN", user_id=row["id"])
    logger.info("User logged in: %s", row["username"])
    return jsonify({"token": token, "role": row["role"]})

@app.route("/equipment", methods=["GET"])
@require_auth

def list_equipment():
    db = get_db()
    rows = db.execute(
    "SELECT id, name, location, status FROM equipment LIMIT ?",
    (MAX_ROWS,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/equipment", methods=["POST"])
@require_auth
@require_role("admin", "engineer")

def add_equipment():
    data = request.get_json(silent=True) or {}
    name, err = validate_text(data.get("name"), "name", max_len=100)
    if err:
        return jsonify({"error": err}), 400
    location, err = validate_text(data.get("location"), "location", max_len=100)
    if err:
        return jsonify({"error": err}), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO equipment (name, location) VALUES (?,?)",
        (name, location)
    )
    db.commit()
    equipment_id = cur.lastrowid
    audit("ADD_EQUIPMENT", "equipment", equipment_id,
          f"name={name}", user_id=g.current_user["id"])
    logger.info("Equipment added: %s by %s", name, g.current_user["username"])
    return jsonify({"id": equipment_id, "name": name}), 201


@app.route("/work-orders", methods=["POST"])
@require_auth
@require_role("admin", "engineer")

def create_work_order():
    data = request.get_json(silent=True) or {}
    equipment_id, err = validate_int(data.get("equipment_id"), "equipment_id")
    if err:
        return jsonify({"error": err}), 400
    description, err = validate_text(data.get("description"), "description", max_len=500)
    if err:
        return jsonify({"error": err}), 400

    db = get_db()
    eq = db.execute(
        "SELECT id FROM equipment WHERE id=?", (equipment_id,)
    ).fetchone()
    if not eq:
        return jsonify({"error": "Equipment not found"}), 404

    cur = db.execute(
        "INSERT INTO work_orders (equipment_id, description, created_by) VALUES (?,?,?)",
        (equipment_id, description, g.current_user["id"])
    )
    db.commit()
    order_id = cur.lastrowid
    audit("CREATE_WORK_ORDER", "work_order", order_id,
          f"equipment_id={equipment_id}", user_id=g.current_user["id"])
    logger.info("Work order created: %d by %s", order_id, g.current_user["username"])
    return jsonify({"id": order_id}), 201


@app.route("/work-orders", methods=["GET"])
@require_auth
def list_work_orders():
    db = get_db()
    user = g.current_user
    allowed_statuses = {"open", "in_progress", "on_hold", "closed"}
    filter_status = request.args.get("status", "")

    conditions = []
    params = []

    if user["role"] == "operator":
        conditions.append("assigned_to = ?")
        params.append(user["id"])

    if filter_status and filter_status in allowed_statuses:
        conditions.append("status = ?")
        params.append(filter_status)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    query = (
        f"SELECT id, equipment_id, description, status, created_at"
        f" FROM work_orders {where} ORDER BY created_at DESC LIMIT ?"
    )
    params.append(MAX_ROWS)
    rows = db.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/work-orders/<int:order_id>/status", methods=["PATCH"])
@require_auth
@require_role("admin", "engineer")

def update_status(order_id):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "")
    allowed = {"open", "in_progress", "on_hold", "closed"}
    if new_status not in allowed:
        return jsonify({"error": f"Invalid status. Allowed: {sorted(allowed)}"}), 400

    db = get_db()
    order = db.execute(
        "SELECT * FROM work_orders WHERE id=?", (order_id,)
    ).fetchone()
    if not order:
        return jsonify({"error": "Work order not found"}), 404
    if order["status"] == "closed":
        return jsonify({"error": "Cannot change closed work order"}), 400

    allowed, err_resp = check_object_access(order, action="update_status")
    if not allowed:
        return err_resp

    db.execute(
        "UPDATE work_orders SET status=? WHERE id=?", (new_status, order_id)
    )
    db.commit()
    audit("UPDATE_STATUS", "work_order", order_id,
          f"status={new_status}", user_id=g.current_user["id"])
    logger.info("Work order %d status -> %s by %s",
                order_id, new_status, g.current_user["username"])
    return jsonify({"updated": True, "status": new_status})


@app.route("/work-orders/<int:order_id>/close", methods=["POST"])
@require_auth
@require_role("admin", "engineer")

def close_work_order(order_id):
    db = get_db()
    order = db.execute(
        "SELECT * FROM work_orders WHERE id=?", (order_id,)
    ).fetchone()
    if not order:
        return jsonify({"error": "Work order not found"}), 404
    if order["status"] == "closed":
        return jsonify({"error": "Already closed"}), 400

    allowed, err_resp = check_object_access(order, action="close")
    if not allowed:
        return err_resp

    db.execute(
        "UPDATE work_orders SET status='closed' WHERE id=?", (order_id,)
    )
    db.commit()
    audit("CLOSE_WORK_ORDER", "work_order", order_id,
          user_id=g.current_user["id"])
    logger.info("Work order %d closed by %s", order_id, g.current_user["username"])
    return jsonify({"closed": True})



@app.route("/report", methods=["GET"])
@require_auth
@require_role("admin", "engineer")
def export_report():
    db = get_db()
    rows = db.execute(
        """
        SELECT wo.id, wo.description, wo.status, wo.created_at,
               e.name AS equipment_name,
               u.username AS created_by
        FROM work_orders wo
        JOIN equipment e ON e.id = wo.equipment_id
        JOIN users u ON u.id = wo.created_by
        ORDER BY wo.created_at DESC
        """
    ).fetchall()
    audit("EXPORT_REPORT", user_id=g.current_user["id"])
    logger.info("Report exported by %s", g.current_user["username"])
    response = jsonify([dict(r) for r in rows])
    response.headers["Content-Disposition"] = "attachment; filename=report.json"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/work-orders/<int:order_id>/assign", methods=["POST"])
@require_auth
@require_role("admin")

def assign_work_order(order_id):
    data = request.get_json(silent=True) or {}
    engineer_id, err = validate_int(data.get("engineer_id"), "engineer_id")
    if err:
        return jsonify({"error": err}), 400

    db = get_db()
    order = db.execute(
        "SELECT id, status FROM work_orders WHERE id=?", (order_id,)
    ).fetchone()
    if not order:
        return jsonify({"error": "Work order not found"}), 404
    if order["status"] == "closed":
        return jsonify({"error": "Cannot assign closed work order"}), 400

    engineer = db.execute(
        "SELECT id, username FROM users WHERE id=? AND role='engineer'",
        (engineer_id,)
    ).fetchone()
    if not engineer:
        return jsonify({"error": "Engineer not found"}), 404

    db.execute(
        "UPDATE work_orders SET assigned_to=? WHERE id=?",
        (engineer_id, order_id)
    )
    db.commit()
    audit("ASSIGN_WORK_ORDER", "work_order", order_id,
          f"assigned_to={engineer_id}", user_id=g.current_user["id"])
    logger.info("Work order %d assigned to %s by %s",
                order_id, engineer["username"], g.current_user["username"])
    return jsonify({"assigned": True, "engineer": engineer["username"]})


@app.route("/report/csv", methods=["GET"])
@require_auth
@require_role("admin", "engineer")
def export_report_csv():
    db = get_db()
    allowed_statuses = {"open", "in_progress", "on_hold", "closed"}
    filter_status = request.args.get("status", "")

    params = [MAX_ROWS]
    where = ""
    if filter_status and filter_status in allowed_statuses:
        where = "WHERE wo.status = ?"
        params = [filter_status, MAX_ROWS]

    rows = db.execute(
        f"""
        SELECT wo.id, wo.description, wo.status, wo.created_at,
               e.name AS equipment_name, u.username AS created_by
        FROM work_orders wo
        JOIN equipment e ON e.id = wo.equipment_id
        JOIN users u ON u.id = wo.created_by
        {where}
        ORDER BY wo.created_at DESC LIMIT ?
        """,
        params,
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    fieldnames = ["id", "equipment_name", "description",
                  "status", "created_by", "created_at"]
    writer.writerow(fieldnames)
    for row in rows:
        d = dict(row)
        writer.writerow([d.get(f, "") for f in fieldnames])

    csv_data = output.getvalue()
    output.close()

    audit("EXPORT_REPORT_CSV", user_id=g.current_user["id"])
    logger.info("CSV exported by %s", g.current_user["username"])

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=report.csv",
            "X-Content-Type-Options": "nosniff",
        }
    )

@app.route("/admin/users", methods=["POST"])
@require_auth
@require_role("admin")
def create_user():
    data = request.get_json(silent=True) or {}
    username, err = validate_text(data.get("username"), "username", max_len=64)
    if err:
        return jsonify({"error": err}), 400

    password = str(data.get("password", ""))
    if not password or len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if len(password) > MAX_PASSWORD_LEN:
        return jsonify({"error": "password too long"}), 400

    allowed_roles = {"admin", "engineer", "operator"}
    role = data.get("role", "")
    if role not in allowed_roles:
        return jsonify({"error": f"Invalid role. Allowed: {sorted(allowed_roles)}"}), 400

    db = get_db()
    exists = db.execute(
        "SELECT 1 FROM users WHERE username=?", (username,)
    ).fetchone()
    if exists:
        return jsonify({"error": "Username already taken"}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
        (username, hashed, role)
    )
    db.commit()
    new_id = cur.lastrowid
    audit("CREATE_USER", "user", new_id,
          f"username={username} role={role}", user_id=g.current_user["id"])
    logger.info("User created: %s role=%s by %s",
                username, role, g.current_user["username"])
    return jsonify({"id": new_id, "username": username, "role": role}), 201

if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)