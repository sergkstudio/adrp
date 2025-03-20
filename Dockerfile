# Используем официальный образ Python
FROM python:3.9-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем зависимости
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код приложения
COPY . .

# Создаем базу данных SQLite (если она еще не создана)
RUN python -c "from models import db; db.create_all()"

# Открываем порт 5000 для Flask
EXPOSE 5000

# Запускаем приложение
CMD ["python", "app.py"]