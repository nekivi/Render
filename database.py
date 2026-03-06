from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base
import os

# URL базы данных будет браться из переменных окружения на Render
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/messenger")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Создает таблицы при первом запуске"""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Генератор сессий БД для FastAPI"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()