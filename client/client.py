import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import asyncio
import requests
import websockets
import json
import os
from datetime import datetime
import base64

from crypto_utils import CryptoManager
import config

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Messenger - Вход")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        self.crypto = CryptoManager()
        self.username = None
        self.logged_in = False
        
        self.setup_ui()
        
    def setup_ui(self):
        # Заголовок
        title = tk.Label(self.root, text="Безопасный мессенджер", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=20)
        
        # Фрейм для входа
        login_frame = ttk.LabelFrame(self.root, text="Вход / Регистрация", padding=10)
        login_frame.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Поле логина
        ttk.Label(login_frame, text="Логин:").grid(row=0, column=0, sticky="w", pady=5)
        self.login_entry = ttk.Entry(login_frame, width=30)
        self.login_entry.grid(row=0, column=1, pady=5, padx=5)
        
        # Поле пароля
        ttk.Label(login_frame, text="Пароль:").grid(row=1, column=0, sticky="w", pady=5)
        self.password_entry = ttk.Entry(login_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, pady=5, padx=5)
        
        # Кнопки
        button_frame = ttk.Frame(login_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Вход", command=self.login, width=15).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Регистрация", command=self.register, width=15).pack(side="left", padx=5)
        
        # Статус
        self.status_label = ttk.Label(self.root, text="", foreground="blue")
        self.status_label.pack(pady=5)
        
        # Привязываем Enter к входу
        self.password_entry.bind("<Return>", lambda e: self.login())
        
    def login(self):
        """Вход в систему"""
        username = self.login_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Ошибка", "Введите логин и пароль")
            return
        
        self.status_label.config(text="Вход...")
        self.root.update()
        
        try:
            # Отправляем запрос на сервер
            response = requests.post(
                f"{config.SERVER_URL}/login",
                json={"username": username, "password": password}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Проверяем, есть ли сохраненные ключи
                if os.path.exists(config.KEY_FILE):
                    with open(config.KEY_FILE, 'r') as f:
                        keys = json.load(f)
                        if username in keys:
                            # Загружаем приватный ключ
                            self.crypto.load_private_key(keys[username])
                            self.username = username
                            self.logged_in = True
                            self.root.destroy()
                            return
                
                # Если ключей нет, просим зарегистрироваться заново
                messagebox.showerror("Ошибка", "Ключи не найдены. Используйте регистрацию.")
                self.status_label.config(text="")
            else:
                error_msg = response.json().get("detail", "Ошибка входа")
                messagebox.showerror("Ошибка", error_msg)
                self.status_label.config(text="")
                
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу: {e}")
            self.status_label.config(text="")
    
    def register(self):
        """Регистрация нового пользователя"""
        username = self.login_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Ошибка", "Введите логин и пароль")
            return
        
        if len(password) < 6:
            messagebox.showerror("Ошибка", "Пароль должен быть не менее 6 символов")
            return
        
        self.status_label.config(text="Регистрация...")
        self.root.update()
        
        try:
            # Генерируем ключи
            self.status_label.config(text="Генерация ключей...")
            self.root.update()
            public_key = self.crypto.generate_rsa_keys()
            
            # Отправляем запрос на сервер
            response = requests.post(
                f"{config.SERVER_URL}/register",
                json={
                    "username": username,
                    "password": password,
                    "public_key": public_key
                }
            )
            
            if response.status_code == 200:
                # Сохраняем приватный ключ локально
                keys = {}
                if os.path.exists(config.KEY_FILE):
                    with open(config.KEY_FILE, 'r') as f:
                        keys = json.load(f)
                
                keys[username] = self.crypto.get_private_key_pem()
                
                with open(config.KEY_FILE, 'w') as f:
                    json.dump(keys, f)
                
                # Сохраняем текущего пользователя
                with open(config.CONFIG_FILE, 'w') as f:
                    json.dump({"last_user": username}, f)
                
                self.username = username
                self.logged_in = True
                self.root.destroy()
            else:
                error_msg = response.json().get("detail", "Ошибка регистрации")
                messagebox.showerror("Ошибка", error_msg)
                self.status_label.config(text="")
                
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу: {e}")
            self.status_label.config(text="")
    
    def run(self):
        self.root.mainloop()
        return self.username if self.logged_in else None


class MainWindow:
    def __init__(self, username, crypto):
        self.root = tk.Tk()
        self.root.title(f"Messenger - {username}")
        self.root.geometry("900x600")
        
        self.username = username
        self.crypto = crypto
        self.contacts = {}  # имя -> публичный ключ
        self.current_chat = None
        self.messages = []  # список сообщений для текущего чата
        self.ws_connection = None
        self.loop = asyncio.new_event_loop()
        
        # Запускаем WebSocket в отдельном потоке
        self.ws_thread = threading.Thread(target=self.start_ws_loop, daemon=True)
        self.ws_thread.start()
        
        self.setup_ui()
        self.load_contacts()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def start_ws_loop(self):
        """Запускает asyncio цикл для WebSocket в отдельном потоке"""
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.websocket_handler())
    
    async def websocket_handler(self):
        """Обработчик WebSocket соединения"""
        uri = f"{config.WS_URL}/ws/{self.username}"
        try:
            async with websockets.connect(uri) as websocket:
                self.ws_connection = websocket
                # Отправляем ping каждые 30 секунд для поддержания соединения
                while True:
                    try:
                        # Ждем сообщения от сервера
                        message = await asyncio.wait_for(websocket.recv(), timeout=30)
                        data = json.loads(message)
                        
                        if data["type"] == "new_message":
                            # Есть новое сообщение, загружаем его
                            self.root.after(0, self.check_new_messages)
                            
                    except asyncio.TimeoutError:
                        # Отправляем ping
                        await websocket.send("ping")
                    except websockets.exceptions.ConnectionClosed:
                        break
        except Exception as e:
            print(f"WebSocket error: {e}")
    
    def setup_ui(self):
        """Создание интерфейса"""
        # Главный фрейм
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Левая панель - контакты
        left_frame = ttk.Frame(main_frame, width=250)
        left_frame.pack(side="left", fill="y", padx=(0, 5))
        left_frame.pack_propagate(False)
        
        # Заголовок контактов
        ttk.Label(left_frame, text="Контакты", font=("Arial", 12, "bold")).pack(pady=5)
        
        # Кнопка добавления контакта
        ttk.Button(left_frame, text="+ Добавить контакт", 
                  command=self.add_contact_dialog).pack(pady=5, padx=5, fill="x")
        
        # Список контактов
        self.contacts_listbox = tk.Listbox(left_frame, bg="white", selectmode=tk.SINGLE)
        self.contacts_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.contacts_listbox.bind('<<ListboxSelect>>', self.on_contact_select)
        
        # Правая панель - чат
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True)
        
        # Заголовок чата
        self.chat_header = ttk.Label(right_frame, text="Выберите контакт", 
                                     font=("Arial", 12, "bold"))
        self.chat_header.pack(pady=5)
        
        # Область сообщений
        self.messages_text = scrolledtext.ScrolledText(
            right_frame, wrap=tk.WORD, state='disabled', height=20
        )
        self.messages_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Фрейм для ввода сообщения
        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill="x", padx=5, pady=5)
        
        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        ttk.Button(input_frame, text="Отправить", command=self.send_message).pack(side="right")
        
    def load_contacts(self):
        """Загружает список контактов"""
        try:
            # Временно добавляем тестовые контакты
            # TODO: Загружать из истории переписки
            self.contacts_listbox.delete(0, tk.END)
            for contact in self.contacts.keys():
                self.contacts_listbox.insert(tk.END, contact)
        except Exception as e:
            print(f"Error loading contacts: {e}")
    
    def add_contact_dialog(self):
        """Диалог добавления контакта"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Добавить контакт")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Введите имя пользователя:").pack(pady=10)
        entry = ttk.Entry(dialog, width=30)
        entry.pack(pady=5)
        entry.focus()
        
        status_label = ttk.Label(dialog, text="")
        status_label.pack(pady=5)
        
        def add():
            contact = entry.get().strip()
            if not contact:
                return
            
            if contact == self.username:
                messagebox.showerror("Ошибка", "Нельзя добавить самого себя")
                return
            
            status_label.config(text="Поиск пользователя...")
            dialog.update()
            
            try:
                # Запрашиваем публичный ключ пользователя
                response = requests.get(f"{config.SERVER_URL}/users/{contact}")
                
                if response.status_code == 200:
                    data = response.json()
                    self.contacts[contact] = data["public_key"]
                    self.load_contacts()
                    dialog.destroy()
                    
                    # Автоматически открываем чат с новым контактом
                    self.current_chat = contact
                    self.chat_header.config(text=f"Чат с {contact}")
                    self.messages_text.config(state='normal')
                    self.messages_text.delete(1.0, tk.END)
                    self.messages_text.config(state='disabled')
                else:
                    status_label.config(text="Пользователь не найден", foreground="red")
                    
            except requests.exceptions.RequestException as e:
                status_label.config(text=f"Ошибка: {e}", foreground="red")
        
        ttk.Button(dialog, text="Добавить", command=add).pack(pady=10)
    
    def on_contact_select(self, event):
        """Обработчик выбора контакта"""
        selection = self.contacts_listbox.curselection()
        if selection:
            self.current_chat = self.contacts_listbox.get(selection[0])
            self.chat_header.config(text=f"Чат с {self.current_chat}")
            
            # Очищаем и загружаем историю сообщений
            self.messages_text.config(state='normal')
            self.messages_text.delete(1.0, tk.END)
            
            # TODO: Загрузить историю сообщений из локального хранилища
            
            self.messages_text.config(state='disabled')
            
            # Проверяем новые сообщения
            self.check_new_messages()
    
    def send_message(self):
        """Отправка сообщения"""
        if not self.current_chat:
            messagebox.showinfo("Инфо", "Выберите контакт для отправки сообщения")
            return
        
        message_text = self.message_entry.get().strip()
        if not message_text:
            return
        
        self.message_entry.delete(0, tk.END)
        
        # Отображаем свое сообщение сразу
        self.display_message(self.username, message_text)
        
        # Отправляем в отдельном потоке
        threading.Thread(target=self.send_message_thread, 
                        args=(message_text,), daemon=True).start()
    
    def send_message_thread(self, message_text):
        """Отправка сообщения в фоновом потоке"""
        try:
            # Получаем публичный ключ получателя
            recipient_key = self.contacts.get(self.current_chat)
            if not recipient_key:
                # Запрашиваем с сервера
                response = requests.get(f"{config.SERVER_URL}/users/{self.current_chat}")
                if response.status_code == 200:
                    data = response.json()
                    recipient_key = data["public_key"]
                    self.contacts[self.current_chat] = recipient_key
                else:
                    self.root.after(0, lambda: messagebox.showerror(
                        "Ошибка", "Не удалось получить ключ получателя"
                    ))
                    return
            
            # Шифруем сообщение
            encrypted = self.crypto.encrypt_for_recipient(message_text, recipient_key)
            
            # Отправляем на сервер
            response = requests.post(
                f"{config.SERVER_URL}/messages?sender={self.username}",
                json={
                    "recipient": self.current_chat,
                    "ciphertext": encrypted["ciphertext"],
                    "nonce": encrypted["nonce"],
                    "tag": encrypted["tag"],
                    "encrypted_key": encrypted["encrypted_key"]
                }
            )
            
            if response.status_code != 200:
                self.root.after(0, lambda: messagebox.showerror(
                    "Ошибка", "Не удалось отправить сообщение"
                ))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror(
                "Ошибка", f"Ошибка отправки: {e}"
            ))
    
    def check_new_messages(self):
        """Проверяет новые сообщения"""
        if not self.current_chat:
            return
        
        try:
            response = requests.get(f"{config.SERVER_URL}/messages/{self.username}")
            if response.status_code == 200:
                data = response.json()
                for msg in data["messages"]:
                    if msg["sender"] == self.current_chat:
                        # Дешифруем сообщение
                        try:
                            plaintext = self.crypto.decrypt_from_sender({
                                "ciphertext": msg["ciphertext"],
                                "nonce": msg["nonce"],
                                "tag": msg["tag"],
                                "encrypted_key": msg["encrypted_key"]
                            })
                            self.display_message(msg["sender"], plaintext)
                        except Exception as e:
                            print(f"Decryption error: {e}")
        except Exception as e:
            print(f"Error checking messages: {e}")
    
    def display_message(self, sender, text):
        """Отображает сообщение в окне чата"""
        self.messages_text.config(state='normal')
        
        # Вставляем время
        timestamp = datetime.now().strftime("%H:%M")
        
        if sender == self.username:
            self.messages_text.insert(tk.END, f"[{timestamp}] Вы: ", "self_prefix")
        else:
            self.messages_text.insert(tk.END, f"[{timestamp}] {sender}: ", "other_prefix")
        
        self.messages_text.insert(tk.END, f"{text}\n\n", "message")
        
        # Настройка тегов для раскраски
        self.messages_text.tag_config("self_prefix", foreground="blue", font=("Arial", 10, "bold"))
        self.messages_text.tag_config("other_prefix", foreground="green", font=("Arial", 10, "bold"))
        self.messages_text.tag_config("message", font=("Arial", 10))
        
        self.messages_text.see(tk.END)
        self.messages_text.config(state='disabled')
    
    def on_closing(self):
        """Обработчик закрытия окна"""
        if self.ws_connection:
            asyncio.run_coroutine_threadsafe(self.ws_connection.close(), self.loop)
        self.loop.stop()
        self.root.destroy()


def main():
    # Показываем окно входа
    login = LoginWindow()
    username = login.run()
    
    if username:
        # Загружаем ключи
        crypto = CryptoManager()
        with open(config.KEY_FILE, 'r') as f:
            keys = json.load(f)
            crypto.load_private_key(keys[username])
        
        # Запускаем главное окно
        app = MainWindow(username, crypto)
        app.root.mainloop()

if __name__ == "__main__":
    main()