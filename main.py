from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Dict
import json
import datetime
import asyncio

from database import get_db, init_db
from models import User, Message
from passlib.context import CryptContext
from pydantic import BaseModel

# Для хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# Разрешаем CORS для любого происхождения (на продакшене лучше ограничить)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# При запуске создаем таблицы
@app.on_event("startup")
def startup():
    init_db()

# ---- Модели Pydantic для API ----
class UserCreate(BaseModel):
    username: str
    password: str
    public_key: str

class UserLogin(BaseModel):
    username: str
    password: str

class MessageSend(BaseModel):
    recipient: str
    ciphertext: str
    nonce: str

# ---- HTTP API (регистрация, логин, отправка) ----

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя"""
    # Проверяем, существует ли уже такой пользователь
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Хешируем пароль
    hashed_password = pwd_context.hash(user.password)
    
    # Создаем нового пользователя
    new_user = User(
        username=user.username,
        password_hash=hashed_password,
        public_key=user.public_key
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"status": "ok", "message": "User created"}

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    """Логин пользователя"""
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    # Проверяем пароль
    if not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid password")
    
    # Обновляем время последнего визита
    db_user.last_seen = datetime.datetime.utcnow()
    db.commit()
    
    return {
        "status": "ok", 
        "username": db_user.username,
        "public_key": db_user.public_key
    }

@app.get("/users/{username}")
def get_user(username: str, db: Session = Depends(get_db)):
    """Получить публичный ключ пользователя"""
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "username": db_user.username,
        "public_key": db_user.public_key
    }

@app.post("/messages")
async def send_message(message: MessageSend, username: str, db: Session = Depends(get_db)):
    """
    Отправка сообщения.
    username - кто отправляет (берется из заголовка, но для простоты передадим как параметр)
    """
    # Проверяем, существует ли получатель
    recipient = db.query(User).filter(User.username == message.recipient).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Сохраняем сообщение
    db_message = Message(
        sender=username,
        recipient=message.recipient,
        ciphertext=message.ciphertext,
        nonce=message.nonce
    )
    
    db.add(db_message)
    db.commit()
    
    # Если получатель онлайн (есть WebSocket соединение), пытаемся отправить сразу
    if message.recipient in active_connections:
        # Отправляем уведомление о новом сообщении
        await active_connections[message.recipient].send_json({
            "type": "new_message",
            "sender": username,
            "timestamp": str(db_message.timestamp)
        })
    
    return {"status": "ok", "message_id": db_message.id}

@app.get("/messages/{username}")
def get_undelivered_messages(username: str, db: Session = Depends(get_db)):
    """Получить все недоставленные сообщения для пользователя"""
    messages = db.query(Message).filter(
        Message.recipient == username,
        Message.delivered == 0
    ).all()
    
    result = []
    for msg in messages:
        result.append({
            "id": msg.id,
            "sender": msg.sender,
            "ciphertext": msg.ciphertext,
            "nonce": msg.nonce,
            "timestamp": str(msg.timestamp)
        })
        # Помечаем как доставленные
        msg.delivered = 1
    
    db.commit()
    
    return {"messages": result}

# ---- WebSocket для реального времени ----
active_connections: Dict[str, WebSocket] = {}

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await websocket.accept()
    
    # Сохраняем соединение
    active_connections[username] = websocket
    
    try:
        while True:
            # Ждем сообщения от клиента (можем использовать для поддержания соединения)
            data = await websocket.receive_text()
            # Пока просто игнорируем, можно добавить heartbeat
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        # При отключении удаляем из активных соединений
        if username in active_connections:
            del active_connections[username]

# Для запуска: uvicorn main:app --reload
