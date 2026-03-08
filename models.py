from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime
import uuid

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
    tag = Column(Text, nullable=False)
    encrypted_key = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    delivered = Column(Integer, default=0)

class Group(Base):
    __tablename__ = "groups"
    
    id = Column(Integer, primary_key=True)
    group_id = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    creator = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    avatar = Column(Text, nullable=True)
    
    def __init__(self, **kwargs):
        if 'group_id' not in kwargs:
            kwargs['group_id'] = str(uuid.uuid4())
        super().__init__(**kwargs)

class GroupMember(Base):
    __tablename__ = "group_members"
    
    id = Column(Integer, primary_key=True)
    group_id = Column(String(50), index=True, nullable=False)
    username = Column(String(50), index=True, nullable=False)
    joined_at = Column(DateTime, default=datetime.datetime.utcnow)
    role = Column(String(20), default="member")  # admin, member
    
    __table_args__ = (UniqueConstraint('group_id', 'username', name='unique_group_member'),)

class GroupMessage(Base):
    __tablename__ = "group_messages"
    
    id = Column(Integer, primary_key=True)
    group_id = Column(String(50), index=True, nullable=False)
    sender = Column(String(50), nullable=False)
    ciphertext = Column(Text, nullable=False)
    nonce = Column(Text, nullable=False)
    tag = Column(Text, nullable=False)
    encrypted_key = Column(Text, nullable=False)  # Для групповых сообщений это маркер
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    delivered = Column(Integer, default=0)  # 0 - не доставлено, 1 - доставлено

class GroupKey(Base):
    __tablename__ = "group_keys"
    
    id = Column(Integer, primary_key=True)
    group_id = Column(String(50), index=True, nullable=False)
    username = Column(String(50), index=True, nullable=False)
    encrypted_key = Column(Text, nullable=False)  # Ключ группы, зашифрованный для пользователя
    key_version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('group_id', 'username', name='unique_group_key'),)
