FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY certs/ ./certs/
COPY frontend/ ./frontend/
COPY .env.example .env

EXPOSE 5000

CMD ["python", "app/main.py"]