import sqlite3
import bcrypt
import os
import sys

# Загружаем env ДО импорта main, чтобы DB_PATH был правильным
from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, 'app')
from main import init_db

# init_db создаёт таблицы и базовых пользователей
init_db()

DB_PATH = os.environ.get("DB_PATH", "oil_gas.db")
print(f"Seeding database: {DB_PATH}")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# ── Оборудование (50 единиц) ──────────────────────────────────────────────────
types    = ["Pump", "Valve", "Compressor", "Generator", "Filter",
            "Sensor", "Motor", "Tank", "Pipe", "Boiler"]
sections = ["Section A", "Section B", "Section C", "Section D", "Section E"]

added_eq = 0
for i in range(1, 51):
    name     = f"{types[i % len(types)]}-{i:02d}"
    location = sections[i % len(sections)]
    exists   = cur.execute("SELECT 1 FROM equipment WHERE name=?", (name,)).fetchone()
    if not exists:
        cur.execute("INSERT INTO equipment (name, location) VALUES (?,?)", (name, location))
        added_eq += 1

# ── Пользователи (10 инженеров + 5 операторов) ────────────────────────────────
seed_users = []
for i in range(2, 12):   # engineer2..engineer11
    seed_users.append((f"engineer{i}", f"Eng{i}pass1", "engineer"))
for i in range(2, 7):    # operator2..operator6
    seed_users.append((f"operator{i}", f"Op{i}pass1", "operator"))

added_users = 0
for username, password, role in seed_users:
    exists = cur.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if not exists:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            (username, hashed, role)
        )
        added_users += 1

# ── Заявки (150 штук) ─────────────────────────────────────────────────────────
import random
random.seed(42)  # воспроизводимость

statuses = ["open", "in_progress", "on_hold", "closed"]
descriptions = [
    "Плановое ТО", "Замена фильтра", "Проверка давления",
    "Калибровка датчика", "Ремонт утечки", "Замена масла",
    "Проверка электрики", "Очистка системы", "Замена прокладки",
    "Диагностика вибрации"
]

# Получаем реальные ID пользователей-инженеров
engineer_ids = [row[0] for row in
    cur.execute("SELECT id FROM users WHERE role='engineer' LIMIT 11").fetchall()]
eq_count = cur.execute("SELECT COUNT(*) FROM equipment").fetchone()[0]

added_orders = 0
existing_orders = cur.execute("SELECT COUNT(*) FROM work_orders").fetchone()[0]

if existing_orders < 10:   # seed только если таблица почти пустая
    for i in range(1, 151):
        eq_id      = (i % eq_count) + 1
        desc       = f"{random.choice(descriptions)} #{i}"
        status     = random.choice(statuses)
        created_by = random.choice(engineer_ids) if engineer_ids else 2
        cur.execute(
            "INSERT INTO work_orders (equipment_id, description, status, created_by) VALUES (?,?,?,?)",
            (eq_id, desc, status, created_by)
        )
        added_orders += 1

conn.commit()
conn.close()

print(f"  Equipment added : {added_eq}")
print(f"  Users added     : {added_users}")
print(f"  Work orders     : {added_orders}")
print("Seed complete.")
