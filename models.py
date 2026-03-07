from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    public_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(50), index=True, nullable=False)
    recipient = Column(String(50), index=True, nullable=False)
    ciphertext = Column(Text, nullable=False)      # Зашифрованное сообщение
    nonce = Column(Text, nullable=False)           # Nonce для AES
    tag = Column(Text, nullable=False)             # Тег аутентификации GCM
    encrypted_key = Column(Text, nullable=False)   # Зашифрованный RSA ключ
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    delivered = Column(Integer, default=0)          # 0 - не доставлено, 1 - доставлено

# Настройки базы данных
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
