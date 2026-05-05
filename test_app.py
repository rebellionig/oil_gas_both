import sys
import os
import threading
import time
import json
import urllib.request

os.environ.setdefault("JWT_SECRET_KEY", "actuallykindalongenoughsecretkey")
os.environ.setdefault("DB_PATH", "test_oil_gas.db")

sys.path.insert(0, "app")
import main
main.init_db()

t = threading.Thread(
    target=lambda: main.app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False),
    daemon=True
)
t.start()
time.sleep(1.5)

BASE = "http://127.0.0.1:5001"

def post(path, data, token=None):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        BASE + path, data=body,
        headers={"Content-Type": "application/json"}
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except:
            return {}, e.code

def get(path, token=None):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except:
            return {}, e.code

def patch(path, data, token=None):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        BASE + path, data=body, method="PATCH",
        headers={"Content-Type": "application/json"}
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except:
            return {}, e.code

results = []

# Логины
r, c = post("/login", {"username": "admin", "password": "admin123"})
adm = r.get("token", "")
results.append(("LOGIN admin", c, c == 200, r.get("role")))

r, c = post("/login", {"username": "engineer1", "password": "engineer1"})
eng = r.get("token", "")
results.append(("LOGIN engineer1", c, c == 200, r.get("role")))

r, c = post("/login", {"username": "operator1", "password": "operator1"})
op = r.get("token", "")
results.append(("LOGIN operator1", c, c == 200, r.get("role")))

# Без токена
r, c = get("/equipment")
results.append(("GET /equipment no auth → 401", c, c == 401, ""))

# С токеном
r, c = get("/equipment", eng)
results.append(("GET /equipment with token → 200", c, c == 200, f"{len(r)} items"))

# Создать заявку
r, c = post("/work-orders", {"equipment_id": 1, "description": "Test order"}, eng)
results.append(("POST /work-orders → 201", c, c == 201, r))

# Назначить заявку
r, c = post("/work-orders/1/assign", {"engineer_id": 2}, adm)
results.append(("POST /assign → 200", c, c == 200, r))

# Сменить статус
r, c = patch("/work-orders/1/status", {"status": "in_progress"}, eng)
results.append(("PATCH /status → 200", c, c == 200, r))

# Operator не может создать заявку
r, c = post("/work-orders", {"equipment_id": 1, "description": "test"}, op)
results.append(("operator POST /work-orders → 403", c, c == 403, ""))

# SQL injection
r, c = post("/login", {"username": "admin' --", "password": "x"})
results.append(("SQL injection → 401", c, c == 401, ""))

# Неверный пароль
r, c = post("/login", {"username": "engineer1", "password": "wrong"})
results.append(("Wrong password → 401", c, c == 401, r.get("error", "")))

# Отчёт
r, c = get("/report", eng)
results.append(("GET /report → 200", c, c == 200, f"{len(r)} rows"))

# Operator не видит отчёт
r, c = get("/report", op)
results.append(("GET /report operator → 403", c, c == 403, ""))

# CSV экспорт — отдельная проверка без JSON парсинга
import urllib.request as _ur2
rq_csv = _ur2.Request("http://127.0.0.1:5001/report/csv")
rq_csv.add_header("Authorization", f"Bearer {eng}")
try:
    with _ur2.urlopen(rq_csv) as rr:
        c_csv = rr.status
except urllib.error.HTTPError as e:
    c_csv = e.code
results.append(("GET /report/csv → 200", c_csv, c_csv == 200, ""))

# operator не может получить CSV
rq_csv2 = _ur2.Request("http://127.0.0.1:5001/report/csv")
rq_csv2.add_header("Authorization", f"Bearer {op}")
try:
    with _ur2.urlopen(rq_csv2) as rr:
        c_csv2 = rr.status
except urllib.error.HTTPError as e:
    c_csv2 = e.code
results.append(("GET /report/csv operator → 403", c_csv2, c_csv2 == 403, ""))

# admin создаёт пользователя
r, c = post("/admin/users", {"username": "neweng", "password": "Password123", "role": "engineer"}, adm)
results.append(("POST /admin/users → 201", c, c == 201, r))

# engineer не может создать пользователя
r, c = post("/admin/users", {"username": "hack", "password": "Password123", "role": "admin"}, eng)
results.append(("engineer POST /admin/users → 403", c, c == 403, ""))

# Неверная роль при создании
r, c = post("/admin/users", {"username": "test99", "password": "Password123", "role": "superuser"}, adm)
results.append(("invalid role → 400", c, c == 400, ""))

# Тело > 16KB → 413
import urllib.request as _ur
big = ("x" * 20000).encode()
rq = _ur.Request("http://127.0.0.1:5001/login", data=big, headers={"Content-Type": "application/json"})
try:
    with _ur.urlopen(rq) as rr: c413 = rr.status
except urllib.error.HTTPError as e: c413 = e.code
results.append(("Body > 16KB → 413", c413, c413 == 413, ""))

# Пароль > 128 символов → 401
r, c = post("/login", {"username": "engineer1", "password": "A" * 200})
results.append(("Password > 128 chars → 401", c, c == 401, ""))

print()
print("РЕЗУЛЬТАТЫ ТЕСТОВ")
print("=" * 60)
for name, code, passed, detail in results:
    mark = "PASS" if passed else "FAIL"
    print(f"  {mark} [{code}] {name}")
    if not passed:
        print(f"       -> {detail}")
print("=" * 60)
ok = sum(1 for _, _, p, _ in results if p)
print(f"Итог: {ok}/{len(results)} тестов пройдено")

# Удалить тестовую БД
import os as _os
try:
    _os.remove("test_oil_gas.db")
except:
    pass