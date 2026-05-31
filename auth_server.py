import json
import os
import secrets
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys

# Import the listener's function
from websocket_listener import start_session, SESSION_FILE, RESULT_FILE

app = Flask(__name__)
CORS(app)

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")
    sys.stdout.flush()

@app.route('/api/create_session', methods=['POST'])
def create_session():
    session_id = secrets.token_urlsafe(16)
    log(f"Create session {session_id}")

    # Start the WebSocket session in the background listener
    auth_url = start_session(session_id)

    if auth_url:
        log(f"Session {session_id} created: {auth_url}")
        return jsonify({'session_id': session_id, 'auth_url': auth_url, 'status': 'pending'})
    else:
        log(f"Session {session_id} failed to generate URL")
        return jsonify({'error': 'Failed to generate link'}), 500

@app.route('/api/check_status/<session_id>', methods=['GET'])
def check_status(session_id):
    # Look for completed result
    if os.path.exists(RESULT_FILE):
        with open(RESULT_FILE, 'r') as f:
            results = json.load(f)
            if session_id in results:
                user_data = results[session_id]
                log(f"Session {session_id} completed, returning token")
                # Clean up old entries (optional)
                return jsonify({'status': 'completed', 'user_data': user_data})
    return jsonify({'status': 'pending'})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
