# ADRP

Проект на Flask для изменения пароля пользователями в MS AD.

## Требования

- Python 3.x
- Docker и Docker Compose (опционально)

## Установка

### Локальный запуск

1. Создайте виртуальное окружение:
```bash
python -m venv venv
source venv/bin/activate  # для Linux/Mac
# или
.\venv\Scripts\activate  # для Windows
```

2. Установите зависимости:
```bash
pip install -r requirements.txt
```

3. Запустите приложение:
```bash
python app/app.py
```

### Запуск через Docker

1. Соберите и запустите контейнеры:
```bash
docker-compose up --build
```

Приложение будет доступно по адресу: http://localhost:5000

## Зависимости

- Flask 2.3.0 - веб-фреймворк
- ldap3 2.9.1 - библиотека для работы с LDAP
- python-dotenv 0.19.2 - загрузка переменных окружения
- requests 2.28.1 - HTTP-клиент

## Структура проекта

```
.
├── app/                    # Основной код приложения
├── Dockerfile             # Конфигурация Docker
├── docker-compose.yml     # Конфигурация Docker Compose
├── requirements.txt       # Зависимости проекта
└── .gitignore            # Игнорируемые Git файлы
```

## Разработка

Проект настроен для разработки с использованием Docker. При внесении изменений в код, они будут автоматически отображаться благодаря настроенным volumes в docker-compose.yml.

## Лицензия

MIT 