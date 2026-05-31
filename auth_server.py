#!/usr/bin/env python3
"""
Discord Remote Auth Server - For Render.com Deployment
Handles authentication via Discord's remote-auth gateway
"""

import base64
import json
import threading
import time
import os
import sys
import websocket
import requests
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Store active auth sessions
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

class DiscordUser:
    def __init__(self, **values):
        self.id = values.get('id')
        self.username = values.get('username')
        self.discrim = values.get('discriminator')
        self.avatar_hash = values.get('avatar')
        self.token = values.get('token')

class AuthSession:
    def __init__(self, session_id):
        self.session_id = session_id
        self.auth_ws = None
        self.user_data = None
        self.completed = False
        self.created_at = time.time()
        self.auth_url = None
        
    def start_auth(self):
        """Start the authentication process"""
        self.auth_ws = DiscordAuthWebsocket(self)
        thread = threading.Thread(target=self.auth_ws.run)
        thread.daemon = True
        thread.start()
        
        # Wait for fingerprint (max 5 seconds)
        timeout = 5
        while not self.auth_url and timeout > 0:
            time.sleep(0.1)
            timeout -= 0.1
            if self.auth_ws.current_fingerprint:
                self.auth_url = f"https://discord.com/ra/{self.auth_ws.current_fingerprint}"
        
        return self.auth_url

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
        
    @property
    def public_key(self):
        pub_key = self.key.publickey().export_key().decode('utf-8')
        pub_key = ''.join(pub_key.split('\n')[1:-1])
        return pub_key

    def run(self):
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
            payload.update(**data)
        if self.ws and self.ws.sock and self.ws.sock.connected:
            self.ws.send(json.dumps(payload))

    def heartbeat_sender(self):
        while not self.should_stop:
            time.sleep(0.5)
            if self.last_heartbeat and self.heartbeat_interval:
                current_time = time.time()
                if current_time - self.last_heartbeat >= self.heartbeat_interval:
                    self.send(Messages.HEARTBEAT)
                    self.last_heartbeat = current_time

    def decrypt_payload(self, encrypted_payload):
        payload = base64.b64decode(encrypted_payload)
        return self.cipher.decrypt(payload)

    def on_open(self, ws):
        self.send(Messages.INIT, {'encoded_public_key': self.public_key})

    def on_message(self, ws, message):
        try:
            data = json.loads(message)
            op = data.get('op')
            
            if op == Messages.HELLO:
                self.heartbeat_interval = data.get('heartbeat_interval') / 1000
                self.last_heartbeat = time.time()
                thread = threading.Thread(target=self.heartbeat_sender)
                thread.daemon = True
                thread.start()
                
            elif op == Messages.NONCE_PROOF:
                nonce = data.get('encrypted_nonce')
                decrypted_nonce = self.decrypt_payload(nonce)
                proof = SHA256.new(data=decrypted_nonce).digest()
                proof = base64.urlsafe_b64encode(proof).decode().rstrip('=')
                self.send(Messages.NONCE_PROOF, {'proof': proof})
                
            elif op == Messages.PENDING_REMOTE_INIT:
                self.current_fingerprint = data.get('fingerprint')
                print(f"[Auth] Session {self.session.session_id}: Link generated")
                
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
                print(f"[Auth] Session {self.session.session_id}: User {values[3]}#{values[1]} authenticated")
                
            elif op == Messages.PENDING_LOGIN:
                ticket = data.get('ticket')
                response = requests.post(self.LOGIN_ENDPOINT, json={'ticket': ticket})
                if response.status_code == 200:
                    encrypted_token = response.json().get('encrypted_token')
                    token = self.decrypt_payload(encrypted_token)
                    self.session.user_data['token'] = token.decode()
                    self.session.completed = True
                    print(f"[Auth] Session {self.session.session_id}: Token obtained")
                    self.should_stop = True
                    ws.close()
                    
        except Exception as e:
            print(f"[Error] {e}")

    def on_error(self, ws, error):
        print(f"[WebSocket Error] {error}")

    def on_close(self, ws, status_code, msg):
        print(f"[WebSocket Closed] {status_code}: {msg}")

@app.route('/api/create_session', methods=['POST'])
def create_session():
    """Create a new auth session and return the link"""
    session_id = secrets.token_urlsafe(16)
    session = AuthSession(session_id)
    active_sessions[session_id] = session
    
    auth_url = session.start_auth()
    
    if auth_url:
        return jsonify({
            'session_id': session_id,
            'auth_url': auth_url,
            'status': 'pending'
        })
    else:
        return jsonify({'error': 'Failed to generate auth link'}), 500

@app.route('/api/check_status/<session_id>', methods=['GET'])
def check_status(session_id):
    """Check if authentication is complete"""
    session = active_sessions.get(session_id)
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    
    # Clean up old sessions (older than 5 minutes)
    current_time = time.time()
    for sid, sess in list(active_sessions.items()):
        if current_time - sess.created_at > 300:
            del active_sessions[sid]
    
    if session.completed and session.user_data:
        return jsonify({
            'status': 'completed',
            'user_data': session.user_data
        })
    else:
        return jsonify({'status': 'pending'})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'active_sessions': len(active_sessions)})

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'service': 'Discord Auth Server',
        'status': 'running',
        'endpoints': ['/api/create_session', '/api/check_status/<session_id>', '/api/health']
    })

if __name__ == '__main__':
    print(f"""
    ╔════════════════════════════════════════╗
    ║     Discord Auth Server                ║
    ║     Running on port {PORT}                ║
    ╚════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=PORT, debug=False)
