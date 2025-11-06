#!/usr/bin/python3
# -*- coding: utf-8 -*-
# |
import socket
import sqlite3
import requests
import threading
import os, re, uuid, time, json, datetime
from flask import Flask, Response, request, session, redirect, render_template, url_for, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = 'segredo_super_seguro'
CORS(app)

DATABASE = 'app.db'
JSON_FILE = "/var/www/opentty/assets/root/web.json"
EXPIRATION_TIMES = { '5min': 5, '10min': 10, '1hour': 60, '1day': 1440, '1week': 10080, '2week': 20160, '1month': 43200, '6months': 259200, '1year': 525600 }


connections = {}

def handle_client(conn, addr):
    try:
        print(f'[TCP] New connection from {addr}')
        conn.sendall(b'Password: ')
        password = conn.recv(1024).decode().strip()

        conn_id = str(uuid.uuid4())[:8]

        connections[conn_id] = {'conn': conn, 'addr': addr, 'password': password, 'buffer': '', 'in_use': False, 'disconnected': False}

        print(f'[TCP] Autheticated. ID: {conn_id} | IP: {addr} | Password: {password}')
        conn.sendall(f'Connected. Your ID is {conn_id}\n'.encode())

        conn.settimeout(0.5)

        while True:
            try:
                data = conn.recv(1024)
                if not data: break

                msg = data.decode()
                print(f'[TCP] GET {conn_id}: {msg.strip()}')
                connections[conn_id]['buffer'] += msg
            except socket.timeout: continue
    except Exception as e: print(f'[TCP] Error on {addr}: {e}')
    finally:
        print(f'[TCP] Connection finished from {addr}')
        for k, v in connections.items():
            if v['conn'] == conn:
                print(f'[TCP] Mark {k} as disconnected')
                v['disconnected'] = True
        conn.close()
def start_tcp_server(host='0.0.0.0', port=4096):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(31522)
    print(f'[TCP] Server listening on {host}:{port}')

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def load_versions():
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"downloads": [], "news": []}

# WebProxy
# | 
@app.route('/cli/')
def webproxy(): return render_template('login.html')
# | (Login Page)
@app.route('/cli/login', methods=['POST'])
def login():
    conn_id = request.form['conn_id']
    password = request.form['password']

    conn_data = connections.get(conn_id)

    errors = []
    if not conn_data: errors.append("Invalid ID")
    if conn_data['password'] != password: errors.append("Invalid password")
    if conn_data['in_use']: errors.append("Busy session")
    if conn_data.get('disconnected', False): errors.append("Connection closed")

    if errors: return render_template("login.html", errors=errors)

    conn_data['in_use'] = True
    session['conn_id'] = conn_id
    return redirect(url_for('terminal'))
# | (Proxy Page)
@app.route('/cli/terminal')
def terminal():
    if 'conn_id' not in session: return redirect('/cli/')
    return render_template('terminal.html')
# |
# | (Write API)
@app.route('/cli/send', methods=['POST'])
def send_command():
    if 'conn_id' not in session: return 'Unauthorized', 401

    conn_id = session['conn_id']
    data = request.json
    command = data.get('command', '')

    conn_data = connections.get(conn_id)
    if not conn_data: return 'Invalid session', 400 
    if conn_data.get('disconnected', False): return 'Connection closed', 400

    try:
        conn_data['conn'].sendall((command + '\n').encode())
        print(f"[FLASK] Payload '{command}' forwarded for {conn_id}")
        return 'Sent', 200
    except Exception as e:
        print(f"[FLASK] Forwarding error: {e}")
        return f'Error: {e}', 500
# | (Read API)
@app.route('/cli/receive')
def receive_data():
    if 'conn_id' not in session: return 'Unauthorized', 401

    conn_id = session['conn_id']
    conn_data = connections.get(conn_id)

    if not conn_data or conn_data.get('disconnected', False): return jsonify({'output': '', 'redirect': '/cli/'}) 

    start = time.time()
    while time.time() - start < 25:
        output = conn_data['buffer']
        if output:
            conn_data['buffer'] = ''
            return jsonify({'output': output})
        time.sleep(0.2)

    return jsonify({'output': ''})
# | (Get ID of current session)
@app.route('/cli/session')
def get_session():
    if 'conn_id' not in session: return jsonify({"active": False}), 401

    conn_id = session['conn_id']
    conn_data = connections.get(conn_id)
    if not conn_data or conn_data.get('disconnected', False): return jsonify({"active": False}), 400

    return jsonify({"active": True, "id": conn_id})
# | (Leave session)
@app.route('/cli/disconnect', methods=['POST'])
def disconnect():
    conn_id = session.get('conn_id')
    if conn_id:
        conn_data = connections.get(conn_id)
        if conn_data:
            conn_data['in_use'] = False
            conn_data['disconnected'] = False
            
        session.pop('conn_id', None)
    return 'OK', 200


# DeepBin
# |
# (Database)
# | (Initalize SQLite table)
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS pastes (id TEXT PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL, syntax TEXT, expires DATETIME, unlisted BOOLEAN DEFAULT FALSE, created DATETIME DEFAULT CURRENT_TIMESTAMP)")
    conn.commit()
    conn.close()
# |
init_db()
# |
# (Utilities)
# | (Get expiration date)
def calculate_expiration(expires_str):
    now = datetime.datetime.now()
    
    expires_map = {'never': None, '5min': datetime.timedelta(minutes=5), '10min': datetime.timedelta(minutes=10), '1hour': datetime.timedelta(hours=1), '1day': datetime.timedelta(days=1), '1week': datetime.timedelta(weeks=1), '2week': datetime.timedelta(weeks=2), '1month': datetime.timedelta(days=30), '6months': datetime.timedelta(days=180), '1year': datetime.timedelta(days=365)}
    
    if expires_str in expires_map:
        if expires_str == 'never': return None

        return now + expires_map[expires_str]
    return now + datetime.timedelta(days=1)
# | (Check if Paste is expired)
def is_paste_expired(expires_datetime):
    if expires_datetime is None: return False
    
    if isinstance(expires_datetime, str): expires_datetime = datetime.datetime.fromisoformat(expires_datetime)
    
    return datetime.datetime.now() > expires_datetime
# |
# | (Create Paste)
def create_paste(title, content, syntax, expires, unlisted=False):
    paste_id = str(uuid.uuid4())[:16] if unlisted else str(uuid.uuid4())[:8]
    expires_dt = calculate_expiration(expires)
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("INSERT INTO pastes (id, title, content, syntax, expires, unlisted) VALUES (?, ?, ?, ?, ?, ?)", 
                  (paste_id, title, content, syntax, expires_dt.isoformat() if expires_dt else None, unlisted))
    
    conn.commit()
    conn.close()
    
    return paste_id
# | (Get Paste)
def get_paste(paste_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM pastes WHERE id = ?', (paste_id,))
    paste = cursor.fetchone()
    conn.close()
    
    if not paste: return None
    
    if paste[4] is not None and is_paste_expired(paste[4]):
        delete_paste(paste_id)
        return None
    
    return {'id': paste[0], 'title': paste[1], 'content': paste[2], 'syntax': paste[3], 'expires': paste[4], 'unlisted': bool(paste[5]), 'created': paste[6]}
# | (Delete Paste)
def delete_paste(paste_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM pastes WHERE id = ?', (paste_id,))
    conn.commit()
    conn.close()
# |
# (Flask API)
# | (Main Page)
@app.route('/')
def index(): return render_template('index.html')
# | (Create API)
@app.route('/create', methods=['POST'])
def create_paste_route():
    data = request.get_json() if request.is_json else request.form
    
    title = data.get('title', 'Untitled')
    content = data.get('content', '')
    syntax = data.get('syntax', 'text')
    expires = data.get('expires', '1day')
    unlisted = data.get('unlisted', False)
    
    if not content: return jsonify({'error': 'Content is required'}), 400
    
    paste_id = create_paste(title, content, syntax, expires, unlisted)
    
    return jsonify({'success': True, 'paste_id': paste_id, 'url': f'/{paste_id}', 'unlisted': unlisted})
# | (View Paste on Web)
@app.route('/<paste_id>')
def view_paste(paste_id):
    password = request.args.get('password')
    paste = get_paste(paste_id)
    
    if not paste: return jsonify({'error': 'Paste not found or expired'}), 404
    
    return jsonify(paste)
# | (Read Paste)
@app.route('/api/paste/<paste_id>')
def api_paste_raw(paste_id):
    password = request.args.get('password')
    paste = get_paste(paste_id, password)
    
    if not paste: return 'Paste not found or expired', 404
    
    return paste['content']
# |
# (Socket)
def handle_client_connection(client_socket):
    try:
        data = client_socket.recv(1024).decode('utf-8').strip()
        parts = data.split(' ', 2)
        
        command = parts[0].upper()
        
        if command == 'READ':
            if len(parts) < 2:
                client_socket.send(b'ERROR 400 Missing paste ID')
                return
            
            paste_id = parts[1]
            password = parts[2] if len(parts) > 2 else None
            
            paste = get_paste(paste_id, password)
            
            if not paste: client_socket.send(b'ERROR 404 Paste not found or expired')
            else: client_socket.send(paste['content'].encode('utf-8'))
        elif command == 'INFO':
            if len(parts) < 2:
                client_socket.send(b'ERROR 400 Missing paste ID')
                return
            
            paste_id = parts[1]
            password = parts[2] if len(parts) > 2 else None
            
            paste = get_paste(paste_id, password)
            
            if not paste: client_socket.send(b'ERROR 404 Paste not found or expired')
            else:
                info_response = paste.copy()
                del info_response['content']
                client_socket.send(json.dumps(info_response).encode('utf-8'))
        elif command == 'WRITE':
            if len(parts) < 2:
                client_socket.send(b'ERROR Missing JSON data')
                return
            
            try:
                json_data = json.loads(parts[1])
                
                title = json_data.get('title', 'Untitled')
                content = json_data.get('content', '')
                syntax = json_data.get('syntax', 'text')
                expires = json_data.get('expires', '1day')
                unlisted = json_data.get('unlisted', False)
                
                if not content:
                    client_socket.send(b'ERROR 409 Content is required')
                    return
                
                paste_id = create_paste(title, content, syntax, expires, unlisted)
                
                response = { 'success': True, 'paste_id': paste_id, 'url': f'/{paste_id}', 'unlisted': unlisted}
                client_socket.send(json.dumps(response).encode('utf-8'))
                
            except json.JSONDecodeError: client_socket.send(b'ERROR 403 Invalid JSON')
        else: client_socket.send(b'ERROR 404 Unknown command')
    except Exception as e: client_socket.send(f'ERROR 500 {str(e)}'.encode('utf-8'))
    finally: client_socket.close()
# | (Run)
def start_socket_server(host='0.0.0.0', port=31523):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(31522)
    
    print(f"[+] DeepBin listening on {host}:{port}")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Socket connection from {addr}")
        client_thread = threading.Thread(target=handle_client_connection, args=(client_socket,), daemon=True).start()

# Reader API
# | (JSON)
@app.route("/api/json", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def info_json(): return jsonify({ "address": request.headers.get('X-Forwarded-For', request.remote_addr), "port": request.environ.get('REMOTE_PORT'), "agent": request.headers.get('User-Agent'), "method": request.method, })
# | (Read IP Address API)
@app.route("/api/ip")
def ip_only(): return Response(request.headers.get('X-Forwarded-For', request.remote_addr), mimetype='text/plain')
# | (Read User-Agent API)
@app.route("/api/ua")
def user_agent_only(): return Response(request.headers.get('User-Agent'), mimetype='text/plain')
# | (Read Request Headers)
@app.route("/api/headers")
def headers_plaintext():
    headers = ""
    for key, value in request.headers.items(): 
        headers += f"{key}: {value}\n"
    return Response(headers, mimetype='text/plain')
# | (Debugging POST API)
@app.route("/api/post", methods=["POST"])
def post():
    client_ip = request.remote_addr
    client_port = request.environ.get("REMOTE_PORT")

    body = request.get_data(as_text=True)

    print("=" * 40)
    print(f"📥 Connection from: {client_ip}:{client_port}")
    print(f"📡 Path: {request.path}")
    print(f"📦 Headers: {dict(request.headers)}")
    print(f"📝 Payload:\n{body}")
    print("=" * 40)

    return f"POST received with sucess!\nContent: {body}\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

# OpenTTY WebSite API
# | (Get Latest Versions)
@app.route("/api/versions")
def get_versions(): return jsonify(load_versions())
# | (Get Download URL)
@app.route("/api/versions/downloads")
def get_downloads(): return jsonify(load_versions().get("downloads", []))
# | (Get News of Developers)
@app.route("/api/versions/news")
def get_news(): return jsonify(load_versions().get("news", []))


if __name__ == '__main__':
    threading.Thread(target=start_tcp_server, daemon=True).start()
    threading.Thread(target=start_socket_server, daemon=True).start()
    app.run(host='127.0.0.1', port=10141, debug=False, use_reloader=False)
