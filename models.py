from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

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
    ciphertext = Column(Text, nullable=False)
    nonce = Column(Text, nullable=False)
    tag = Column(Text, nullable=False)  # Новое поле
    encrypted_key = Column(Text, nullable=False)  # Новое поле
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    delivered = Column(Integer, default=0)
