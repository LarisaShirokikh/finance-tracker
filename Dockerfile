FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Установка Poetry
RUN pip install poetry

# Копирование файлов конфигурации Poetry
COPY pyproject.toml ./

# Настройка Poetry
RUN poetry config virtualenvs.create false

# Установка зависимостей (исключаем dev зависимости)
RUN poetry install --only main

# Копирование кода приложения
COPY ./app ./app
COPY ./.env ./.env

# Создание пользователя без root прав
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser /app
USER appuser

# Экспозиция порта
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Запуск приложения
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]