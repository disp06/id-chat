/**
 * ID Secret Chat — клиентская логика (Web Crypto + Socket.IO)
 */

// DOM elements
const roomIdInput = document.getElementById('room-id');
const secretInput = document.getElementById('secret');
const passwordInput = document.getElementById('password');
const userIdInput = document.getElementById('user-id');
const genRoomIdBtn = document.getElementById('gen-room-id');
const genSecretBtn = document.getElementById('gen-secret');
const genUserIdBtn = document.getElementById('gen-user-id');
const createRoomBtn = document.getElementById('create-room');
const joinRoomBtn = document.getElementById('join-room');
const chatPanel = document.getElementById('chat-panel');
const chatRoomId = document.getElementById('chat-room-id');
const myUserId = document.getElementById('my-user-id');
const messagesContainer = document.getElementById('messages-container');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const leaveBtn = document.getElementById('leave-btn');

let socket = null;
let roomKey = null; // CryptoKey

// ---------- Helpers ----------

function generateRandomId(bytes = 8) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  // base64url encode, cut to ~11 chars
  const b64 = btoa(String.fromCharCode(...arr));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '').slice(0, 11);
}

function base64UrlToArrayBuffer(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = 4 - (b64.length % 4);
  if (padLen !== 4) b64 += '='.repeat(padLen);
  const binary = atob(b64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
  return arr;
}

function arrayBufferToBase64Url(buf) {
  let binary = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importAesKey(keyBytes) {
  return await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptMessage(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, tagLength: 128 },
    key,
    data
  );
  // Combine IV + ciphertext+tag
  const combined = new Uint8Array(iv.byteLength + cipherBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuffer), iv.byteLength);
  return arrayBufferToBase64Url(combined);
}

async function decryptMessage(tokenBase64Url, key) {
  const data = base64UrlToArrayBuffer(tokenBase64Url);
  const iv = data.slice(0, 12);
  const ciphertext = data.slice(12); // includes tag (last 16 bytes)
  try {
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      key,
      ciphertext
    );
    const decoder = new TextDecoder();
    return decoder.decode(plainBuffer);
  } catch (e) {
    console.error('Decryption failed', e);
    return '[DECRYPTION ERROR]';
  }
}

function prependMessage(sender, ciphertext, ts) {
  const el = document.createElement('div');
  el.className = 'mb-2 p-2 border rounded bg-light';
  el.innerHTML = `<small class="text-muted">${new Date(ts * 1000).toLocaleTimeString()} <strong>${sender}</strong>:</small>
                  <div class="message-cipher" data-cipher="${ciphertext}">[зашифровано]</div>`;
  messagesContainer.appendChild(el);
  // Decrypt in place
  if (roomKey) {
    decryptMessage(ciphertext, roomKey).then(plain => {
      el.querySelector('.message-cipher').textContent = plain;
    });
  }
}

function clearMessages() {
  messagesContainer.innerHTML = '';
}

// ---------- Event handlers ----------

genRoomIdBtn.onclick = () => {
  const id = generateRandomId(6); // 6 bytes -> ~8 base64 chars
  roomIdInput.value = id;
};

genSecretBtn.onclick = () => {
  // 32 random bytes -> 44 base64 chars
  const secret = generateRandomId(32);
  secretInput.value = secret;
};

genUserIdBtn.onclick = () => {
  userIdInput.value = generateRandomId(8);
};

createRoomBtn.onclick = async () => {
  const password = passwordInput.value;
  const resp = await fetch('/rooms/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password })
  });
  if (!resp.ok) {
    alert('Create failed: ' + (await resp.text()));
    return;
  }
  const data = await resp.json();
  roomIdInput.value = data.room_id;
  secretInput.value = data.secret;
  alert('Room created. Share room ID and secret with friends.');
};

joinRoomBtn.onclick = async () => {
  const roomId = roomIdInput.value.trim();
  const secret = secretInput.value.trim();
  const password = passwordInput.value;
  if (!roomId || !secret) {
    alert('Room ID and Secret required');
    return;
  }
  const resp = await fetch(`/rooms/${encodeURIComponent(roomId)}/join`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret, password })
  });
  if (!resp.ok) {
    const err = await resp.json();
    alert('Join failed: ' + (err.error || resp.statusText));
    return;
  }
  // Derive key from secret (if no password)
  try {
    const keyBytes = base64UrlToArrayBuffer(secret);
    if (keyBytes.byteLength !== 32) throw new Error('Secret must decode to 32 bytes');
    roomKey = await importAesKey(keyBytes);
  } catch (e) {
    alert('Invalid secret format');
    return;
  }
  // Init chat
  initChat(roomId);
};

function initChat(roomId) {
  chatPanel.classList.remove('d-none');
  chatRoomId.textContent = roomId;
  myUserId.textContent = userIdInput.value || generateRandomId(8);
  clearMessages();

  // Fetch history
  fetch(`/rooms/${encodeURIComponent(roomId)}/messages`)
    .then(r => r.json())
    .then(data => {
      for (const m of data.messages) {
        prependMessage(m.sender, m.ciphertext, m.ts);
      }
    })
    .catch(console.error);

  // Connect socket
  socket = io();
  const myId = myUserId.textContent;
  socket.emit('join', { room_id: roomId, user_id: myId });

  socket.on('joined', (data) => {
    console.log('Joined room', data);
  });

  socket.on('message', (data) => {
    prependMessage(data.sender, data.ciphertext, data.ts);
  });

  socket.on('error', (data) => {
    alert('Error: ' + data.msg);
  });
}

sendBtn.onclick = async () => {
  const text = messageInput.value.trim();
  if (!text || !roomKey) return;
  const ciphertext = await encryptMessage(text, roomKey);
  socket.emit('message', {
    room_id: chatRoomId.textContent,
    user_id: myUserId.textContent,
    ciphertext: ciphertext
  });
  messageInput.value = '';
};

leaveBtn.onclick = () => {
  if (socket) {
    socket.emit('leave', { room_id: chatRoomId.textContent, user_id: myUserId.textContent });
    socket.disconnect();
    socket = null;
  }
  chatPanel.classList.add('d-none');
  roomKey = null;
};

// Auto-generate on load
window.onload = () => {
  genRoomIdBtn.click();
  genSecretBtn.click();
  genUserIdBtn.click();
};
