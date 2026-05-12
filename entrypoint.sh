#!/bin/bash
set -e

echo "=== OilField MMS startup ==="
echo "DB_PATH: ${DB_PATH:-oil_gas.db}"
echo "PORT: ${PORT:-5000}"

# Инициализация БД и seed данных
python seed_data.py

echo "=== Starting Flask ==="
python app/main.py
