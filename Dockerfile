FROM python:3.9-slim

WORKDIR /app

# Копируем .env вместе с другими файлами
COPY requirements.txt .
COPY .env .  # В продакшене лучше использовать секреты

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "./app/main.py"]