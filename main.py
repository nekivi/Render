from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Dict
import json
import datetime
import asyncio
import bcrypt
import uuid
from pydantic import BaseModel

from database import get_db, init_db
from models import User, Message, Group, GroupMember, GroupMessage, GroupKey

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

class GroupCreate(BaseModel):
    name: str

class GroupMessageSend(BaseModel):
    group_id: str
    ciphertext: str
    nonce: str
    tag: str
    encrypted_key: str

class GroupKeySend(BaseModel):
    group_id: str
    username: str
    encrypted_key: str

# ---- HTTP API для пользователей и сообщений ----
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя"""
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = hash_password(user.password)
    
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
    
    if not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid password")
    
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
async def send_message(message: MessageSend, sender: str, db: Session = Depends(get_db)):
    """Отправка личного сообщения"""
    recipient = db.query(User).filter(User.username == message.recipient).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
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
            await active_connections[message.recipient].send_json({
                "type": "new_message",
                "sender": sender,
                "timestamp": str(db_message.timestamp)
            })
        except Exception as e:
            print(f"Error sending websocket notification: {e}")
    
    return {"status": "ok", "message_id": db_message.id}

@app.get("/messages/{username}")
def get_undelivered_messages(username: str, db: Session = Depends(get_db)):
    """Получить все недоставленные личные сообщения"""
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
        msg.delivered = 1
    
    db.commit()
    
    return {"messages": result}

@app.get("/messages/history/{username}")
def get_message_history(username: str, db: Session = Depends(get_db)):
    """Получает все личные сообщения для пользователя"""
    messages = db.query(Message).filter(
        Message.recipient == username
    ).order_by(Message.timestamp.desc()).limit(100).all()
    
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
    
    return {"messages": list(reversed(result))}

# ---- API для групповых чатов ----
@app.post("/groups/create")
def create_group(group: GroupCreate, creator: str, db: Session = Depends(get_db)):
    """Создание новой группы"""
    # Создаем группу с автоматической генерацией group_id
    db_group = Group(
        name=group.name,
        creator=creator
    )
    db.add(db_group)
    db.flush()  # Чтобы получить group_id
    
    # Добавляем создателя как админа
    db_member = GroupMember(
        group_id=db_group.group_id,
        username=creator,
        role="admin"
    )
    db.add(db_member)
    
    db.commit()
    
    return {
        "status": "ok",
        "group_id": db_group.group_id,
        "name": db_group.name
    }

@app.post("/groups/{group_id}/add_member")
def add_member(group_id: str, username: str, db: Session = Depends(get_db)):
    """Добавление участника в группу"""
    # Проверяем существование группы
    group = db.query(Group).filter(Group.group_id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Проверяем, существует ли пользователь
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Проверяем, не участник ли уже
    existing = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.username == username
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Already a member")
    
    # Добавляем участника
    db_member = GroupMember(
        group_id=group_id,
        username=username,
        role="member"
    )
    db.add(db_member)
    db.commit()
    
    return {"status": "ok", "username": username}

@app.post("/groups/{group_id}/remove_member")
def remove_member(group_id: str, username: str, requester: str, db: Session = Depends(get_db)):
    """Удаление участника из группы"""
    # Проверяем права (только админ может удалять)
    requester_member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.username == requester
    ).first()
    
    if not requester_member or requester_member.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can remove members")
    
    # Нельзя удалить создателя
    group = db.query(Group).filter(Group.group_id == group_id).first()
    if group.creator == username:
        raise HTTPException(status_code=400, detail="Cannot remove group creator")
    
    # Удаляем участника
    db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.username == username
    ).delete()
    
    db.commit()
    
    return {"status": "ok"}

@app.get("/groups/{group_id}/members")
def get_group_members(group_id: str, db: Session = Depends(get_db)):
    """Получает всех участников группы с их публичными ключами"""
    members = db.query(GroupMember).filter(
        GroupMember.group_id == group_id
    ).all()
    
    result = []
    for member in members:
        user = db.query(User).filter(
            User.username == member.username
        ).first()
        if user:
            result.append({
                "username": member.username,
                "role": member.role,
                "joined_at": str(member.joined_at),
                "public_key": user.public_key
            })
    
    return {"members": result}

@app.get("/groups/user/{username}")
def get_user_groups(username: str, db: Session = Depends(get_db)):
    """Получает все группы пользователя"""
    memberships = db.query(GroupMember).filter(
        GroupMember.username == username
    ).all()
    
    groups = []
    for membership in memberships:
        group = db.query(Group).filter(
            Group.group_id == membership.group_id
        ).first()
        if group:
            groups.append({
                "group_id": group.group_id,
                "name": group.name,
                "role": membership.role,
                "creator": group.creator,
                "created_at": str(group.created_at)
            })
    
    return {"groups": groups}

@app.post("/groups/key")
def save_group_key(key_data: GroupKeySend, db: Session = Depends(get_db)):
    """Сохраняет зашифрованный ключ группы для пользователя"""
    # Проверяем, существует ли группа
    group = db.query(Group).filter(Group.group_id == key_data.group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Проверяем, является ли пользователь участником
    member = db.query(GroupMember).filter(
        GroupMember.group_id == key_data.group_id,
        GroupMember.username == key_data.username
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="User is not a member of this group")
    
    # Сохраняем или обновляем ключ
    existing_key = db.query(GroupKey).filter(
        GroupKey.group_id == key_data.group_id,
        GroupKey.username == key_data.username
    ).first()
    
    if existing_key:
        existing_key.encrypted_key = key_data.encrypted_key
        existing_key.key_version += 1
    else:
        new_key = GroupKey(
            group_id=key_data.group_id,
            username=key_data.username,
            encrypted_key=key_data.encrypted_key
        )
        db.add(new_key)
    
    db.commit()
    
    return {"status": "ok"}

@app.get("/groups/{group_id}/key/{username}")
def get_group_key(group_id: str, username: str, db: Session = Depends(get_db)):
    """Получает зашифрованный ключ группы для пользователя"""
    key = db.query(GroupKey).filter(
        GroupKey.group_id == group_id,
        GroupKey.username == username
    ).first()
    
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return {
        "group_id": key.group_id,
        "username": key.username,
        "encrypted_key": key.encrypted_key,
        "key_version": key.key_version
    }

@app.post("/groups/message")
async def send_group_message(message: GroupMessageSend, sender: str, db: Session = Depends(get_db)):
    """Отправка сообщения в группу"""
    # Проверяем, является ли отправитель участником группы
    member = db.query(GroupMember).filter(
        GroupMember.group_id == message.group_id,
        GroupMember.username == sender
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    # Сохраняем сообщение
    db_message = GroupMessage(
        group_id=message.group_id,
        sender=sender,
        ciphertext=message.ciphertext,
        nonce=message.nonce,
        tag=message.tag,
        encrypted_key=message.encrypted_key
    )
    db.add(db_message)
    db.commit()
    
    # Получаем всех участников группы
    members = db.query(GroupMember).filter(
        GroupMember.group_id == message.group_id
    ).all()
    
    # Уведомляем всех участников онлайн
    for member in members:
        if member.username != sender and member.username in active_connections:
            try:
                await active_connections[member.username].send_json({
                    "type": "group_message",
                    "group_id": message.group_id,
                    "sender": sender,
                    "timestamp": str(db_message.timestamp)
                })
            except Exception as e:
                print(f"Error sending group notification to {member.username}: {e}")
    
    return {"status": "ok", "message_id": db_message.id}

@app.get("/groups/messages/{group_id}/{username}")
def get_undelivered_group_messages(group_id: str, username: str, db: Session = Depends(get_db)):
    """Получает все недоставленные сообщения для группы"""
    # Проверяем, является ли пользователь участником
    member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.username == username
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    messages = db.query(GroupMessage).filter(
        GroupMessage.group_id == group_id,
        GroupMessage.delivered == 0
    ).all()
    
    result = []
    for msg in messages:
        result.append({
            "id": msg.id,
            "group_id": msg.group_id,
            "sender": msg.sender,
            "ciphertext": msg.ciphertext,
            "nonce": msg.nonce,
            "tag": msg.tag,
            "encrypted_key": msg.encrypted_key,
            "timestamp": str(msg.timestamp)
        })
        msg.delivered = 1
    
    db.commit()
    
    return {"messages": result}

@app.get("/groups/messages/history/{group_id}/{username}")
def get_group_message_history(group_id: str, username: str, db: Session = Depends(get_db)):
    """Получает историю сообщений группы"""
    # Проверяем, является ли пользователь участником
    member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.username == username
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    messages = db.query(GroupMessage).filter(
        GroupMessage.group_id == group_id
    ).order_by(GroupMessage.timestamp.desc()).limit(100).all()
    
    result = []
    for msg in messages:
        result.append({
            "id": msg.id,
            "group_id": msg.group_id,
            "sender": msg.sender,
            "ciphertext": msg.ciphertext,
            "nonce": msg.nonce,
            "tag": msg.tag,
            "encrypted_key": msg.encrypted_key,
            "timestamp": str(msg.timestamp)
        })
    
    return {"messages": list(reversed(result))}

# ---- WebSocket для реального времени ----
active_connections: Dict[str, WebSocket] = {}

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await websocket.accept()
    active_connections[username] = websocket
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        if username in active_connections:
            del active_connections[username]
    except Exception as e:
        print(f"WebSocket error for {username}: {e}")
        if username in active_connections:
            del active_connections[username]
