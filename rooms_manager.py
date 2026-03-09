"""
Менеджер комнат — хранение в памяти (или Redis), авто-очистка неактивных комнат.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from typing import Optional, Tuple

logger = logging.getLogger("RoomsManager")

class Room:
    def __init__(self, room_id: str, secret: str, password_salt: Optional[bytes] = None, max_idle: int = 3600):
        self.room_id = room_id
        self.secret = secret  # base64 string (32 bytes)
        self.password_salt = password_salt  # bytes or None
        self.max_idle = max_idle
        self.created_at = time.time()
        self.last_activity = time.time()
        self.messages = deque(maxlen=100)  # храним последние 100 сообщений (ciphertext + sender + ts)
        self.participants = set()  # user_ids
        self.lock = threading.RLock()

    def touch(self):
        with self.lock:
            self.last_activity = time.time()

    def add_message(self, sender: str, ciphertext: str):
        with self.lock:
            self.messages.append({
                "sender": sender,
                "ciphertext": ciphertext,
                "ts": time.time()
            })
            self.touch()

    def get_recent_messages(self, limit: int = 50):
        with self.lock:
            return list(self.messages)[-limit:]

    def is_idle(self) -> bool:
        return (time.time() - self.last_activity) > self.max_idle

class RoomsManager:
    def __init__(self, cleanup_interval: int = 300):
        self.rooms = {}  # room_id -> Room
        self.lock = threading.RLock()
        self.cleanup_interval = cleanup_interval
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        def cleaner():
            while True:
                time.sleep(self.cleanup_interval)
                self.cleanup()
        t = threading.Thread(target=cleaner, daemon=True)
        t.start()

    def cleanup(self):
        with self.lock:
            to_remove = []
            for rid, room in self.rooms.items():
                if room.is_idle():
                    logger.info(f"Removing idle room: {rid}")
                    to_remove.append(rid)
            for rid in to_remove:
                del self.rooms[rid]
            if to_remove:
                logger.info(f"Cleaned up {len(to_remove)} rooms, remaining: {len(self.rooms)}")

    def create_room(self, room_id: str, secret: str, password_salt: Optional[bytes] = None, max_idle: int = 3600) -> Room:
        with self.lock:
            if room_id in self.rooms:
                raise ValueError("Room already exists")
            room = Room(room_id, secret, password_salt, max_idle)
            self.rooms[room_id] = room
            logger.info(f"Created room: {room_id}")
            return room

    def get_room(self, room_id: str) -> Optional[Room]:
        with self.lock:
            room = self.rooms.get(room_id)
            if room:
                room.touch()
            return room

    def remove_room(self, room_id: str):
        with self.lock:
            if room_id in self.rooms:
                del self.rooms[room_id]
                logger.info(f"Removed room: {room_id}")

    def list_rooms(self) -> list:
        with self.lock:
            return list(self.rooms.keys())

# Глобальный менеджер (один на процесс)
rooms_manager = RoomsManager(cleanup_interval=300)
