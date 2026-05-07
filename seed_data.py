import sqlite3
import bcrypt
import os
from dotenv import load_dotenv

import sys
sys.path.insert(0, 'app')
from main import init_db
init_db()

load_dotenv()
DB_PATH = os.environ.get("DB_PATH", "oil_gas.db")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Добавить оборудование (50 единиц)
equipment = []
types = ["Pump", "Valve", "Compressor", "Generator", "Filter",
         "Sensor", "Motor", "Tank", "Pipe", "Boiler"]
sections = ["Section A", "Section B", "Section C", "Section D", "Section E"]

for i in range(1, 51):
    name = f"{types[i % len(types)]}-{i:02d}"
    location = sections[i % len(sections)]
    equipment.append((name, location))

for name, loc in equipment:
    exists = cur.execute("SELECT 1 FROM equipment WHERE name=?", (name,)).fetchone()
    if not exists:
        cur.execute("INSERT INTO equipment (name, location) VALUES (?,?)", (name, loc))

# Добавить пользователей (10 инженеров + 5 операторов)
users = []
for i in range(1, 11):
    users.append((f"engineer{i+1}", f"eng{i+1}pass123", "engineer"))
for i in range(1, 6):
    users.append((f"operator{i+1}", f"op{i+1}pass123", "operator"))

for username, password, role in users:
    exists = cur.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if not exists:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            (username, hashed, role)
        )

# Добавить заявки (150 штук)
import random
statuses = ["open", "in_progress", "on_hold", "closed"]
descriptions = [
    "Плановое ТО", "Замена фильтра", "Проверка давления",
    "Калибровка датчика", "Ремонт утечки", "Замена масла",
    "Проверка электрики", "Очистка системы", "Замена прокладки",
    "Диагностика вибрации"
]

for i in range(1, 151):
    eq_id = (i % 50) + 1
    desc = f"{random.choice(descriptions)} #{i}"
    status = random.choice(statuses)
    created_by = (i % 11) + 1
    cur.execute(
        "INSERT INTO work_orders (equipment_id, description, status, created_by) VALUES (?,?,?,?)",
        (eq_id, desc, status, created_by)
    )

conn.commit()
conn.close()

print("Seed data added:")
print(f"  Equipment: 50")
print(f"  Users: 15 new")
print(f"  Work orders: 150")
print(f"  Total work orders: 150+")