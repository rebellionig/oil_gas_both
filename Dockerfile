FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY certs/ ./certs/
COPY frontend/ ./frontend/
COPY .env.example .env
COPY seed_data.py .
EXPOSE 5000

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
CMD ["./entrypoint.sh"]