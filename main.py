from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Dict, Set
import json
import datetime
import asyncio
import bcrypt
import uuid
from pydantic import BaseModel

from database import engine, get_db, init_db
from models import User, Message, Group, GroupMember, GroupMessage, GroupKey, GroupMessageDelivery, Contact

app = FastAPI()

# Разрешаем CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    # Проверяем наличие колонки deleted в таблице contacts
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    if 'contacts' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('contacts')]
        if 'deleted' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE contacts ADD COLUMN deleted INTEGER DEFAULT 0"))
                conn.commit()
                print("Added 'deleted' column to contacts table")
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
    db_group = Group(
        name=group.name,
        creator=creator
    )
    db.add(db_group)
    db.flush()
    
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
async def add_member(group_id: str, username: str, db: Session = Depends(get_db)):
    """Добавление участника в группу"""
    group = db.query(Group).filter(Group.group_id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    existing = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.username == username
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Already a member")
    
    db_member = GroupMember(
        group_id=group_id,
        username=username,
        role="member"
    )
    db.add(db_member)
    db.commit()
    
    # Уведомляем нового участника
    if username in active_connections:
        try:
            await active_connections[username].send_json({
                "type": "new_group",
                "group_id": group_id
            })
        except Exception as e:
            print(f"Error sending notification to {username}: {e}")
    
    return {"status": "ok", "username": username}

@app.post("/groups/{group_id}/remove_member")
async def remove_member(group_id: str, username: str, requester: str, db: Session = Depends(get_db)):
    """Удаление участника из группы"""
    requester_member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.username == requester
    ).first()
    
    if not requester_member or requester_member.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can remove members")
    
    group = db.query(Group).filter(Group.group_id == group_id).first()
    if group.creator == username:
        raise HTTPException(status_code=400, detail="Cannot remove group creator")
    
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
    print(f"Saving group key for group {key_data.group_id}, user {key_data.username}")
    
    group = db.query(Group).filter(Group.group_id == key_data.group_id).first()
    if not group:
        print(f"Group {key_data.group_id} not found")
        raise HTTPException(status_code=404, detail="Group not found")
    
    member = db.query(GroupMember).filter(
        GroupMember.group_id == key_data.group_id,
        GroupMember.username == key_data.username
    ).first()
    
    if not member:
        print(f"User {key_data.username} is not a member of group {key_data.group_id}, adding...")
        new_member = GroupMember(
            group_id=key_data.group_id,
            username=key_data.username,
            role="member"
        )
        db.add(new_member)
        db.flush()
        print(f"Added {key_data.username} to group as member")
    
    existing_key = db.query(GroupKey).filter(
        GroupKey.group_id == key_data.group_id,
        GroupKey.username == key_data.username
    ).first()
    
    if existing_key:
        existing_key.encrypted_key = key_data.encrypted_key
        existing_key.key_version += 1
        print(f"Updated existing key for {key_data.username}")
    else:
        new_key = GroupKey(
            group_id=key_data.group_id,
            username=key_data.username,
            encrypted_key=key_data.encrypted_key
        )
        db.add(new_key)
        print(f"Created new key for {key_data.username}")
    
    db.commit()
    
    return {"status": "ok", "message": "Group key saved"}

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
    db.flush()
    
    # Получаем всех участников группы
    members = db.query(GroupMember).filter(
        GroupMember.group_id == message.group_id
    ).all()
    
    # Создаём записи о доставке для всех, кроме отправителя
    delivery_count = 0
    for member in members:
        if member.username != sender:
            delivery = GroupMessageDelivery(
                message_id=db_message.id,
                group_id=message.group_id,
                username=member.username,
                delivered=0
            )
            db.add(delivery)
            delivery_count += 1
    
    db.commit()
    print(f"Message {db_message.id} saved, created {delivery_count} delivery records")
    
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
    member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.username == username
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    # Находим ID сообщений, которые уже доставлены этому пользователю
    delivered_subquery = db.query(GroupMessageDelivery.message_id).filter(
        GroupMessageDelivery.group_id == group_id,
        GroupMessageDelivery.username == username,
        GroupMessageDelivery.delivered == 1
    ).subquery()
    
    # Получаем недоставленные сообщения
    messages = db.query(GroupMessage).filter(
        GroupMessage.group_id == group_id,
        ~GroupMessage.id.in_(delivered_subquery)
    ).order_by(GroupMessage.timestamp).all()
    
    print(f"Found {len(messages)} undelivered messages for user {username} in group {group_id}")
    
    result = []
    message_ids = []
    
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
        message_ids.append(msg.id)
    
    # Помечаем как доставленные
    for msg_id in message_ids:
        existing = db.query(GroupMessageDelivery).filter(
            GroupMessageDelivery.message_id == msg_id,
            GroupMessageDelivery.username == username
        ).first()
        
        if existing:
            existing.delivered = 1
            existing.delivered_at = datetime.datetime.utcnow()
        else:
            delivery = GroupMessageDelivery(
                message_id=msg_id,
                group_id=group_id,
                username=username,
                delivered=1,
                delivered_at=datetime.datetime.utcnow()
            )
            db.add(delivery)
    
    db.commit()
    
    return {"messages": result}

@app.get("/groups/messages/all/{username}")
def get_all_undelivered_group_messages(username: str, db: Session = Depends(get_db)):
    """Получает все недоставленные сообщения для всех групп пользователя одним запросом"""
    # Получаем все группы, в которых состоит пользователь
    memberships = db.query(GroupMember).filter(GroupMember.username == username).all()
    group_ids = [m.group_id for m in memberships]
    
    if not group_ids:
        return {"messages": {}}
    
    # Получаем ID сообщений, которые уже доставлены пользователю
    delivered_subquery = db.query(GroupMessageDelivery.message_id).filter(
        GroupMessageDelivery.username == username,
        GroupMessageDelivery.delivered == 1
    ).subquery()
    
    # Получаем все недоставленные сообщения для всех групп
    messages = db.query(GroupMessage).filter(
        GroupMessage.group_id.in_(group_ids),
        ~GroupMessage.id.in_(delivered_subquery)
    ).order_by(GroupMessage.timestamp).all()
    
    # Группируем по group_id
    result = {}
    message_ids = []
    
    for msg in messages:
        if msg.group_id not in result:
            result[msg.group_id] = []
        
        result[msg.group_id].append({
            "id": msg.id,
            "group_id": msg.group_id,
            "sender": msg.sender,
            "ciphertext": msg.ciphertext,
            "nonce": msg.nonce,
            "tag": msg.tag,
            "encrypted_key": msg.encrypted_key,
            "timestamp": str(msg.timestamp)
        })
        message_ids.append(msg.id)
    
    # Помечаем как доставленные
    for msg_id in message_ids:
        existing = db.query(GroupMessageDelivery).filter(
            GroupMessageDelivery.message_id == msg_id,
            GroupMessageDelivery.username == username
        ).first()
        
        if existing:
            existing.delivered = 1
            existing.delivered_at = datetime.datetime.utcnow()
        else:
            delivery = GroupMessageDelivery(
                message_id=msg_id,
                group_id=msg.group_id,
                username=username,
                delivered=1,
                delivered_at=datetime.datetime.utcnow()
            )
            db.add(delivery)
    
    db.commit()
    return {"messages": result}

@app.get("/groups/messages/history/{group_id}/{username}")
def get_group_message_history(group_id: str, username: str, db: Session = Depends(get_db)):
    """Получает историю сообщений группы"""
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

# ---- API для контактов ----
@app.post("/contacts/add")
async def add_contact(user: str, contact: str, db: Session = Depends(get_db)):
    print(f"\n=== ADD CONTACT ===")
    print(f"User {user} adding contact {contact}")
    
    user_exists = db.query(User).filter(User.username == user).first()
    contact_exists = db.query(User).filter(User.username == contact).first()
    if not user_exists or not contact_exists:
        print(f"User not found")
        raise HTTPException(status_code=404, detail="User not found")
    
    # Ищем существующую запись (включая удалённые)
    existing = db.query(Contact).filter(
        Contact.user == user,
        Contact.contact == contact
    ).first()
    
    if existing:
        if existing.deleted:
            print(f"Restoring deleted contact")
            existing.deleted = 0
            existing.mutual = 0
            db.add(existing)
        else:
            print(f"Contact already exists and active")
            return {"status": "already_exists"}
    else:
        # Создаём новую запись
        existing = Contact(user=user, contact=contact, mutual=0, deleted=0)
        db.add(existing)
    
    # Проверяем обратную запись (взаимность)
    reverse = db.query(Contact).filter(
        Contact.user == contact,
        Contact.contact == user
    ).first()
    
    if reverse and not reverse.deleted:
        print(f"Mutual contact detected!")
        existing.mutual = 1
        reverse.mutual = 1
        db.add(reverse)
        
        # Уведомляем обоих
        if user in active_connections:
            await active_connections[user].send_json({
                "type": "contact_mutual",
                "contact": contact
            })
        if contact in active_connections:
            await active_connections[contact].send_json({
                "type": "contact_mutual",
                "contact": user
            })
    else:
        print(f"One-way contact, notifying {contact}")
        if contact in active_connections:
            await active_connections[contact].send_json({
                "type": "new_contact",
                "user": user,
                "public_key": user_exists.public_key
            })
    
    db.commit()
    return {"status": "ok"}

@app.post("/contacts/delete")
async def delete_contact(user: str, contact: str, db: Session = Depends(get_db)):
    """Удаление контакта (мягкое удаление)"""
    print(f"\n=== DELETE CONTACT ===")
    print(f"User {user} deleting contact {contact}")
    
    contact_record = db.query(Contact).filter(
        Contact.user == user,
        Contact.contact == contact
    ).first()
    
    if contact_record:
        contact_record.deleted = 1
        print(f"Marked as deleted")
    
    reverse = db.query(Contact).filter(
        Contact.user == contact,
        Contact.contact == user
    ).first()
    
    if reverse:
        reverse.deleted = 1
        print(f"Marked reverse as deleted")
    
    db.commit()
    return {"status": "ok"}

@app.get("/contacts/{username}")
def get_contacts(username: str, db: Session = Depends(get_db)):
    """Получить список активных контактов пользователя"""
    # Получаем только активные записи (deleted=0)
    as_user = db.query(Contact).filter(
        Contact.user == username,
        Contact.deleted == 0
    ).all()
    as_contact = db.query(Contact).filter(
        Contact.contact == username,
        Contact.deleted == 0
    ).all()
    
    contacts_set = set()
    for c in as_user:
        contacts_set.add(c.contact)
    for c in as_contact:
        contacts_set.add(c.user)
    
    result = []
    for contact in contacts_set:
        user = db.query(User).filter(User.username == contact).first()
        if user:
            result.append({
                "username": contact,
                "public_key": user.public_key,
                "mutual": any(c.mutual for c in as_user if c.contact == contact) or any(c.mutual for c in as_contact if c.user == contact)
            })
    
    return {"contacts": result}

# ---- WebSocket для реального времени и статусов ----
active_connections: Dict[str, WebSocket] = {}

async def notify_contacts_status(username: str, online: bool):
    """Уведомляет всех контактов пользователя об изменении его статуса"""
    try:
        # Получаем список контактов пользователя
        db = next(get_db())
        as_user = db.query(Contact).filter(
            Contact.user == username,
            Contact.deleted == 0
        ).all()
        as_contact = db.query(Contact).filter(
            Contact.contact == username,
            Contact.deleted == 0
        ).all()
        
        contacts_set = set()
        for c in as_user:
            contacts_set.add(c.contact)
        for c in as_contact:
            contacts_set.add(c.user)
        
        db.close()
        
        # Рассылаем уведомления
        for contact in contacts_set:
            if contact in active_connections:
                try:
                    await active_connections[contact].send_json({
                        "type": "status_update",
                        "username": username,
                        "online": online
                    })
                except Exception as e:
                    print(f"Error sending status to {contact}: {e}")
    except Exception as e:
        print(f"Error notifying contacts: {e}")

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await websocket.accept()
    active_connections[username] = websocket
    print(f"WebSocket connected: {username}")
    
    # Уведомляем контакты, что пользователь онлайн
    await notify_contacts_status(username, True)
    
    # Отправляем новому пользователю статусы его контактов
    try:
        db = next(get_db())
        as_user = db.query(Contact).filter(
            Contact.user == username,
            Contact.deleted == 0
        ).all()
        as_contact = db.query(Contact).filter(
            Contact.contact == username,
            Contact.deleted == 0
        ).all()
        
        contacts_set = set()
        for c in as_user:
            contacts_set.add(c.contact)
        for c in as_contact:
            contacts_set.add(c.user)
        
        db.close()
        
        for contact in contacts_set:
            online = contact in active_connections
            await websocket.send_json({
                "type": "status_update",
                "username": contact,
                "online": online
            })
    except Exception as e:
        print(f"Error sending initial statuses: {e}")
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        if username in active_connections:
            del active_connections[username]
        print(f"WebSocket disconnected: {username}")
        # Уведомляем контакты, что пользователь офлайн
        await notify_contacts_status(username, False)
    except Exception as e:
        print(f"WebSocket error for {username}: {e}")
        if username in active_connections:
            del active_connections[username]
        await notify_contacts_status(username, False)
