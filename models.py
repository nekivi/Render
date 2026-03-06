from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=False)  # Хеш пароля
    public_key = Column(Text, nullable=False)  # RSA публичный ключ (в формате PEM)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(50), index=True, nullable=False)
    recipient = Column(String(50), index=True, nullable=False)
    ciphertext = Column(Text, nullable=False)  # Зашифрованное сообщение в base64
    nonce = Column(Text, nullable=False)  # Nonce для AES (тоже base64)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    delivered = Column(Integer, default=0)  # 0 - не доставлено, 1 - доставлено