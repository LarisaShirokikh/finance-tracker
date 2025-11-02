"""
Главный файл FastAPI приложения Finance Tracker

Здесь инициализируется приложение, настраивается CORS,
подключаются роутеры и middleware.

Принципы:
1. Минимальная логика в main.py - только инициализация
2. Все роутеры подключаются через отдельные модули
3. Настройки читаются из конфигурации
4. Middleware настраивается здесь
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

# Импортируем нашу конфигурацию
from app.core.config import settings, get_cors_origins

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


def create_application() -> FastAPI:
    """
    Фабрика для создания FastAPI приложения
    
    Использование фабрики позволяет:
    - Создавать приложение с разными настройками для тестов
    - Лучше контролировать инициализацию
    - Упростить тестирование
    """
    
    app = FastAPI(
        title=settings.project_name,
        description="Система домашнего учета финансов с OAuth авторизацией",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,  # Swagger только в dev
        redoc_url="/redoc" if settings.debug else None,  # ReDoc только в dev
        openapi_url="/openapi.json" if settings.debug else None,
    )
    
    # Настройка CORS для фронтенда
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    
    return app


# Создаем экземпляр приложения
app = create_application()


@app.on_event("startup")
async def startup_event():
    """Событие запуска приложения"""
    logger.info("=== Finance Tracker запускается ===")
    logger.info(f"Режим отладки: {settings.debug}")
    logger.info(f"URL базы данных: {settings.database_url}")
    logger.info(f"Keycloak URL: {settings.keycloak_url}")
    logger.info(f"Keycloak Realm: {settings.keycloak_realm}")
    logger.info("=== Конфигурация загружена ===")


@app.on_event("shutdown")
async def shutdown_event():
    """Событие остановки приложения"""
    logger.info("Finance Tracker останавливается...")


# === БАЗОВЫЕ МАРШРУТЫ ===

@app.get("/")
async def root():
    """Главная страница API"""
    return {
        "message": "Finance Tracker API",
        "version": "0.1.0",
        "status": "running",
        "docs_url": "/docs" if settings.debug else "disabled"
    }


@app.get("/health")
async def health_check():
    """Проверка состояния приложения"""
    return {
        "status": "healthy",
        "timestamp": "2024-11-02T09:00:00Z",
        "version": "0.1.0"
    }


@app.get("/config")
async def get_config():
    """
    Получение конфигурации (только для разработки)
    В продакшене этот endpoint должен быть отключен
    """
    if not settings.debug:
        return JSONResponse(
            status_code=404,
            content={"detail": "Endpoint доступен только в режиме разработки"}
        )
    
    # Возвращаем только безопасные настройки
    return {
        "project_name": settings.project_name,
        "debug": settings.debug,
        "api_v1_prefix": settings.api_v1_prefix,
        "keycloak_url": settings.keycloak_url,
        "keycloak_realm": settings.keycloak_realm,
        "keycloak_client_id": settings.keycloak_client_id,
        "jwt_algorithm": settings.jwt_algorithm,
        "log_level": settings.log_level,
        # НЕ возвращаем секретные данные:
        # - database_url
        # - keycloak_client_secret  
        # - secret_key
    }


# В следующих шагах здесь будут подключены роутеры:
# app.include_router(auth_router, prefix=settings.api_v1_prefix)
# app.include_router(finance_router, prefix=settings.api_v1_prefix)


if __name__ == "__main__":
    """
    Запуск приложения для разработки
    В продакшене используется: gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
    """
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0", 
        port=8000,
        reload=settings.debug,  # Автоперезагрузка только в dev
        log_level=settings.log_level.lower()
    )