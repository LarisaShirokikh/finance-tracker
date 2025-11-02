"""
Конфигурация приложения Finance Tracker

Использует Pydantic Settings для автоматической валидации
и загрузки переменных окружения из .env файла.

Принципы:
1. Все настройки в одном месте
2. Валидация типов автоматически  
3. Переменные окружения перезаписывают значения по умолчанию
4. Разные настройки для dev/test/prod
"""

from typing import List, Optional
from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Настройки приложения с автоматической загрузкой из переменных окружения
    
    Pydantic Settings автоматически:
    - Читает .env файл
    - Преобразует типы данных
    - Валидирует значения
    - Перезаписывает переменными окружения
    """
    
    # === ОСНОВНЫЕ НАСТРОЙКИ ===
    project_name: str = Field(default="Finance Tracker", description="Название проекта")
    debug: bool = Field(default=False, description="Режим отладки")
    api_v1_prefix: str = Field(default="/api/v1", description="Префикс для API v1")
    
    # === БАЗА ДАННЫХ ===
    database_url: str = Field(
        default="postgresql://finance_user:finance_password@localhost:5432/finance_db",
        description="URL подключения к PostgreSQL"
    )
    
    # === KEYCLOAK НАСТРОЙКИ ===
    keycloak_url: str = Field(
        default="http://localhost:8080", 
        description="URL Keycloak сервера"
    )
    keycloak_realm: str = Field(
        default="finance-realm",
        description="Realm в Keycloak для нашего приложения"
    )
    keycloak_client_id: str = Field(
        default="finance-client",
        description="Client ID в Keycloak"
    )
    keycloak_client_secret: Optional[str] = Field(
        default=None,
        description="Client Secret (опционально для публичных клиентов)"
    )
    
    # === JWT НАСТРОЙКИ ===
    jwt_algorithm: str = Field(
        default="RS256",
        description="Алгоритм для JWT (RS256 для Keycloak)"
    )
    access_token_expire_minutes: int = Field(
        default=30,
        description="Время жизни access токена в минутах"
    )
    refresh_token_expire_days: int = Field(
        default=7,
        description="Время жизни refresh токена в днях"
    )
    
    # === БЕЗОПАСНОСТЬ ===
    secret_key: str = Field(
        default="change-this-secret-key-in-production",
        description="Секретный ключ для подписи сессий"
    )
    
    # === CORS ===
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Разрешенные origins для CORS"
    )
    
    # === ЛОГИРОВАНИЕ ===
    log_level: str = Field(
        default="INFO",
        description="Уровень логирования"
    )
    
    @validator("database_url")
    def validate_database_url(cls, v):
        """Проверяем, что URL базы данных корректен"""
        if not v.startswith("postgresql://"):
            raise ValueError("Database URL должен начинаться с postgresql://")
        return v
    
    @validator("keycloak_url")
    def validate_keycloak_url(cls, v):
        """Проверяем, что URL Keycloak корректен"""
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Keycloak URL должен начинаться с http:// или https://")
        return v
    
    @validator("log_level")
    def validate_log_level(cls, v):
        """Проверяем уровень логирования"""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level должен быть одним из: {allowed_levels}")
        return v.upper()

    class Config:
        # Читаем переменные окружения из .env файла
        env_file = ".env"
        env_file_encoding = "utf-8"
        
        # Переменные окружения перезаписывают значения по умолчанию
        case_sensitive = False


# Создаем глобальный экземпляр настроек
# Он автоматически загрузится при импорте модуля
settings = Settings()


def get_database_url() -> str:
    """Получить URL базы данных"""
    return settings.database_url


def get_keycloak_config() -> dict:
    """Получить конфигурацию Keycloak"""
    return {
        "url": settings.keycloak_url,
        "realm": settings.keycloak_realm,
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
    }


def is_development() -> bool:
    """Проверить, находимся ли мы в режиме разработки"""
    return settings.debug


def get_cors_origins() -> List[str]:
    """Получить разрешенные origins для CORS"""
    return settings.allowed_origins