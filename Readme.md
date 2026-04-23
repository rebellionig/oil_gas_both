# Oil & Gas Asset Maintenance MVP

Система технического обслуживания активов нефтегазовой отрасли.

## Стек
- Python 3.14
- Flask 3.1.3
- SQLite
- PyJWT 2.12.0
- bcrypt 4.1.3

## Установка
pip install -r requirements.txt

## Запуск

copy .env.example .env

# Отредактируй .env и установи JWT_SECRET_KEY
python app/main.py


## Эндпоинты
- POST /login
- GET/POST /equipment
- GET/POST /work-orders
- PATCH /work-orders/<id>/status
- POST /work-orders/<id>/close
- POST /work-orders/<id>/assign
- GET /report
- GET /report/csv
- POST /admin/users

## Роли
- admin — полный доступ
- engineer — создание и закрытие своих заявок
- operator — только просмотр своих заявок

## Безопасность
- bcrypt для паролей
- JWT аутентификация (8 часов)
- Параметризованные SQL запросы
- Объектная авторизация
- audit_log для критичных действий
- MAX_CONTENT_LENGTH = 16 KB