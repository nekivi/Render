from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Dict
import json
import datetime
import asyncio
import bcrypt
from pydantic import BaseModel

from database import get_db, init_db
from models import User, Message

app = FastAPI()

# Разрешаем CORS
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

# ---- Вспомогательные функции для паролей ----
def hash_password(password: str) -> str:
    """Хеширует пароль с помощью bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет пароль"""
    return bcrypt.checkpw(
        plain_password.encode('utf-8'), 
        hashed_password.encode('utf-8')
    )

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
    tag: str
    encrypted_key: str

# ---- HTTP API ----
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя"""
    # Проверяем, существует ли уже такой пользователь
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Хешируем пароль
    hashed_password = hash_password(user.password)
    
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
    """Вход пользователя"""
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    # Проверяем пароль
    if not verify_password(user.password, db_user.password_hash):
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
def send_message(message: MessageSend, sender: str, db: Session = Depends(get_db)):
    """
    Отправка сообщения.
    sender - кто отправляет (берется из query параметра)
    """
    # Проверяем, существует ли получатель
    recipient = db.query(User).filter(User.username == message.recipient).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Сохраняем сообщение
    db_message = Message(
        sender=sender,
        recipient=message.recipient,
        ciphertext=message.ciphertext,
        nonce=message.nonce,
        tag=message.tag,
        encrypted_key=message.encrypted_key
    )
    
    db.add(db_message)
    db.commit()
    
    if message.recipient in active_connections:
    try:
        # Получаем event loop или создаем новый
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Если цикл уже запущен, создаем задачу
            asyncio.create_task(
                active_connections[message.recipient].send_json({
                    "type": "new_message",
                    "sender": sender,
                    "timestamp": str(db_message.timestamp)
                })
            )
        else:
            # Если цикла нет, запускаем корутину напрямую
            loop.run_until_complete(
                active_connections[message.recipient].send_json({
                    "type": "new_message",
                    "sender": sender,
                    "timestamp": str(db_message.timestamp)
                })
            )
    except RuntimeError:
        # Если нет event loop, создаем новый и используем его
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            active_connections[message.recipient].send_json({
                "type": "new_message",
                "sender": sender,
                "timestamp": str(db_message.timestamp)
            })
        )
    except Exception as e:
        print(f"Error sending websocket notification: {e}")
    
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
            "tag": msg.tag,
            "encrypted_key": msg.encrypted_key,
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
            # Ждем сообщения от клиента (heartbeat)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        # При отключении удаляем из активных соединений
        if username in active_connections:
            del active_connections[username]
