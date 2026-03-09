#!/usr/bin/env python3
"""
ID SECRET CHAT — анонимный шифрованный чат с комнатами.
"""

import os
import json
import logging
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from rooms_manager import rooms_manager
from crypto import (
    generate_room_secret,
    generate_room_key,
    encrypt_message,
    decrypt_message,
    generate_user_id
)

# Конфиг
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IDSecretChat")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-in-prod')
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=False)

# --- HTTP endpoints ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/rooms/create', methods=['POST'])
def create_room():
    """
    Создание комнаты.
    Тело: { "password": "" | string }
    Возвращает: { "room_id": "...", "secret": "...", "salt": "..." (если пароль) }
    """
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    # Генерация room_id (случайный короткий ID)
    room_id = generate_user_id()[:8]
    secret = generate_room_secret()
    salt = None
    if password:
        key, salt = generate_room_key(secret, password)
    else:
        key, salt = generate_room_key(secret, None)
    # Создаём комнату в менеджере
    rooms_manager.create_room(room_id, secret, salt)
    resp = {"room_id": room_id, "secret": secret}
    if salt:
        resp["salt"] = base64.urlsafe_b64encode(salt).decode('utf-8')
    return jsonify(resp), 201

@app.route('/rooms/<room_id>/join', methods=['POST'])
def join_room_api(room_id):
    """
    Присоединение к комнате.
    Тело: { "secret": "...", "password": "" }
    Возвращает: { "ok": true } или ошибка.
    """
    data = request.get_json(silent=True) or {}
    secret = data.get('secret', '').strip()
    password = data.get('password', '')
    room = rooms_manager.get_room(room_id)
    if not room:
        return jsonify({"error": "Room not found or expired"}), 404
    # Проверяем пароль (если задан)
    if room.password_salt:
        if not password:
            return jsonify({"error": "Password required"}), 403
        try:
            key, _ = generate_room_key(secret, password)
            # Если ключ сгенерирован без ошибок — OK
        except Exception as e:
            return jsonify({"error": "Invalid credentials"}), 403
    else:
        # Без пароля проверяем только secret
        try:
            key, _ = generate_room_key(secret, None)
        except Exception:
            return jsonify({"error": "Invalid secret"}), 403
    return jsonify({"ok": True})

@app.route('/rooms/<room_id>/messages', methods=['GET'])
def get_messages(room_id):
    """
    Получить последние сообщения (ciphertext).
    """
    room = rooms_manager.get_room(room_id)
    if not room:
        return jsonify({"error": "Room not found"}), 404
    msgs = room.get_recent_messages(50)
    # Формат: [{ "sender": "...", "ciphertext": "...", "ts": ... }]
    return jsonify({"messages": msgs})

# --- SocketIO events ---

@socketio.on('join')
def on_join(data):
    room_id = data.get('room_id')
    user_id = data.get('user_id', '')
    if not user_id:
        user_id = generate_user_id()
    room = rooms_manager.get_room(room_id)
    if not room:
        emit('error', {'msg': 'Room not found'})
        return
    join_room(room_id)
    room.touch()
    emit('joined', {'room_id': room_id, 'user_id': user_id})
    logger.info(f"User {user_id} joined room {room_id}")

@socketio.on('leave')
def on_leave(data):
    room_id = data.get('room_id')
    user_id = data.get('user_id', '')
    leave_room(room_id)
    emit('left', {'room_id': room_id, 'user_id': user_id})

@socketio.on('message')
def on_message(data):
    room_id = data.get('room_id')
    user_id = data.get('user_id', 'anonymous')
    ciphertext = data.get('ciphertext', '')
    if not ciphertext:
        emit('error', {'msg': 'Empty message'})
        return
    room = rooms_manager.get_room(room_id)
    if not room:
        emit('error', {'msg': 'Room not found'})
        return
    # Сохраняем в истории
    room.add_message(user_id, ciphertext)
    # Рассылаем всем в комнате (включая отправителя)
    emit('message', {
        'sender': user_id,
        'ciphertext': ciphertext,
        'ts': time.time()
    }, room=room_id)
    logger.debug(f"Message in {room_id} from {user_id}")

# Запуск
if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5537))
    logger.info(f"Starting ID Secret Chat on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=False)
