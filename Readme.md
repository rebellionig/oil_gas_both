# Oil & Gas Asset Maintenance MVP

Система технического обслуживания активов нефтегазовой отрасли.

## Стек
- Python 3.14
- Flask 3.1.3
- SQLite
- PyJWT 2.12.0
- bcrypt 4.1.3
- Docker / Docker Compose


## Запуск через Docker
docker-compose up --build

Сервер: http://localhost:5000

## Локальный запуск
pip install -r requirements.txt
copy .env.example .env
python app/main.py

## Тестовые данные (200+ строк)
python seed_data.py

## Ветки репозитория
- `main` — безопасная версия (P3/P5)
- `vulnerable` — уязвимая версия (для P4)
- `p5` — финальная версия P5

## Эндпоинты
- POST /login
- GET/POST /equipment
- GET/POST /work-orders
- PATCH /work-orders/\<id\>/status
- POST /work-orders/\<id\>/close
- POST /work-orders/\<id\>/assign
- GET /report
- GET /report/csv
- POST /admin/users

## Роли
- admin — полный доступ
- engineer — создание и закрытие своих заявок
- operator — только просмотр своих заявок

## Механизмы безопасности
- bcrypt для паролей (cost=12)
- JWT аутентификация (exp=8h)
- Параметризованные SQL запросы
- Декораторы @require_auth и @require_role
- Объектная авторизация (assigned_to)
- audit_log для критичных действий
- MAX_CONTENT_LENGTH = 16 KB
- Секреты из .env (не в репозитории)
- debug=False в продакшене

## Тестирование

python test_app.py

Результат: 20/20 тестов
