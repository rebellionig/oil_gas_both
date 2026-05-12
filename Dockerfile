FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY frontend/ ./frontend/
COPY seed_data.py .

# Создаём папку для БД
RUN mkdir -p /app/data

EXPOSE 5000

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

CMD ["./entrypoint.sh"]
