#!/usr/bin/python3
# -*- coding: utf-8 -*-
# |
import socket
import sqlite3
import requests
import threading
import uuid, os, time, json, datetime
from flask import Flask, Response, request, session, redirect, render_template, url_for, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
DATABASE = "snakebin.db"
JSON_FILE = "/var/www/opentty/assets/root/web.json"
app.secret_key = 'segredo_super_seguro'
CORS(app)

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS pastes (id TEXT PRIMARY KEY, title TEXT, content TEXT, syntax_highlighting TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME)")
    conn.commit()
    conn.close()
def get_expiration_date(expiration_option):
    now = datetime.now()
    
    if expiration_option == 'never': return None
    elif expiration_option == '5min': return now + timedelta(minutes=5)
    elif expiration_option == '10min': return now + timedelta(minutes=10)
    elif expiration_option == '1hour': return now + timedelta(hours=1)
    elif expiration_option == '1day': return now + timedelta(days=1)
    elif expiration_option == '1week': return now + timedelta(weeks=1) 
    elif expiration_option == '1month': return now + timedelta(days=30)
    else: return None


connections = {}

def handle_client(conn, addr):
    try:
        print(f'[TCP] Nova conexão de {addr}')
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

# SnakeBin
# |
@app.route('/')
def snakebin(): return render_template('index.html')
# |
@app.route('/create', methods=['POST'])
def create_paste():
    try:
        title = request.form.get('title', 'Untitled')
        content = request.form.get('content', '')
        syntax = request.form.get('syntax', 'text')
        expiration = request.form.get('expiration', 'never')
        
        if not content.strip(): return jsonify({'error': 'Content cannot be empty'}), 400
        
        paste_id = str(uuid.uuid4())[:8]
        expires_at = get_expiration_date(expiration)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO pastes (id, title, content, syntax_highlighting, expires_at) VALUES (?, ?, ?, ?, ?)', (paste_id, title, content, syntax, expires_at))
        conn.commit()
        conn.close()
        
        if request.headers.get('Content-Type') == 'application/json': return jsonify({'id': paste_id, 'title': title, 'content': content, 'syntax': syntax, 'expires_at': expires_at.isoformat() if expires_at else None, 'url': f'/{paste_id}'})
        
        return redirect(url_for('view_paste', paste_id=paste_id))
    except Exception as e: return jsonify({'error': str(e)}), 500
# |
@app.route('/<paste_id>')
def view_paste(paste_id):
    if len(paste_id) != 8: return render_template('error.html', error='Invalid paste ID'), 404
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, content, syntax_highlighting, created_at, expires_at FROM pastes WHERE id = ?', (paste_id,))
    paste = cursor.fetchone()
    conn.close()
    
    if not paste: return render_template('error.html', error='Paste not found'), 404
    
    expires_at = paste[5]
    if expires_at and datetime.now() > datetime.fromisoformat(expires_at): return render_template('error.html', error='This paste has expired'), 410
    
    paste_data = {'id': paste[0], 'title': paste[1], 'content': paste[2], 'syntax': paste[3], 'created_at': paste[4], 'expires_at': expires_at}
    
    return render_template('view_paste.html', paste=paste_data)
# |
@app.route('/api/paste/<paste_id>', methods=['GET'])
def api_get_paste(paste_id):
    if len(paste_id) != 8: return jsonify({'error': 'Invalid paste ID'}), 404
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, content, syntax_highlighting, created_at, expires_at FROM pastes WHERE id = ?', (paste_id,))
    paste = cursor.fetchone()
    conn.close()
    
    if not paste: return jsonify({'error': 'Paste not found'}), 404
    
    expires_at = paste[5]
    if expires_at and datetime.now() > datetime.fromisoformat(expires_at): return jsonify({'error': 'This paste has expired'}), 410
    
    return jsonify({'id': paste[0], 'title': paste[1], 'content': paste[2], 'syntax': paste[3], 'created_at': paste[4], 'expires_at': expires_at})
# |
@app.route('/api/create', methods=['POST'])
def api_create_paste():
    try:
        if request.is_json:
            data = request.get_json()
            title = data.get('title', 'Untitled')
            content = data.get('content', '')
            syntax = data.get('syntax', 'text')
            expiration = data.get('expiration', 'never')
        else:
            title = request.form.get('title', 'Untitled')
            content = request.form.get('content', '')
            syntax = request.form.get('syntax', 'text')
            expiration = request.form.get('expiration', 'never')
        
        if not content.strip(): return jsonify({'error': 'Content cannot be empty'}), 400
        
        paste_id = str(uuid.uuid4())[:8]
        expires_at = get_expiration_date(expiration)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO pastes (id, title, content, syntax_highlighting, expires_at) VALUES (?, ?, ?, ?, ?)', (paste_id, title, content, syntax, expires_at))
        conn.commit()
        conn.close()
        
        return jsonify({'id': paste_id, 'title': title, 'content': content, 'syntax': syntax, 'expires_at': expires_at.isoformat() if expires_at else None, 'url': f'/{paste_id}'})
    except Exception as e: return jsonify({'error': str(e)}), 500
# |
# 404 - Paste not found
@app.errorhandler(404)
def not_found(error): return render_template('error.html', error='Page not found'), 404
# |
# | (Clear expired pastes)
def cleanup_expired_pastes():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at < ?', (datetime.now(),))
    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted_count
# |
def handle_snake_cli(conn, addr):
    try:
        print(f'[SnakeBin-CLI] New connection from {addr}')
        data = conn.recv(1024).decode().strip()
        if not data: break
            
        print(f'[SnakeBin-CLI] GET: {data}')
        
        if data.upper().startswith('READ '):
            paste_id = data[5:].strip()
            if len(paste_id) != 8: response = "ERROR: Invalid paste ID"
            
            try:
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()
                cursor.execute('SELECT content, expires_at FROM pastes WHERE id = ?', (paste_id,))
                paste = cursor.fetchone()
                conn.close()
                
                if not paste:
                    response = "ERROR: Paste not found"
                
                expires_at = paste[1]
                if expires_at and datetime.now() > datetime.fromisoformat(expires_at): response = "ERROR: This paste has expired"
                
                response = paste[0]
            except Exception as e: response = f"ERROR: {str(e)}" 
            conn.sendall(response.encode())
        elif data.upper().startswith('INFO '):
            paste_id = data[5:].strip()
            if len(paste_id) != 8: response = "ERROR: Invalid paste ID"
            
            try:
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()
                cursor.execute('SELECT id, title, content, syntax_highlighting, created_at, expires_at FROM pastes WHERE id = ?', (paste_id,))
                paste = cursor.fetchone()
                conn.close()
                
                if not paste: response = "ERROR: Paste not found"
                
                expires_at = paste[5]
                if expires_at and datetime.now() > datetime.fromisoformat(expires_at): response =  "ERROR: This paste has expired"
                
                paste_data = {'id': paste[0], 'title': paste[1], 'content': paste[2], 'syntax': paste[3], 'created_at': paste[4], 'expires_at': expires_at}
                
                response = json.dumps(paste_data, default=str)
            except Exception as e: response = f"ERROR: {str(e)}"
            conn.sendall(response.encode())
        elif data.upper().startswith('WRITE '):
            json_data = data[6:].strip()
            response = ""
            try:
                data = json.loads(json_data)
                
                title = data.get('title', 'Untitled')
                content = data.get('content', '')
                syntax = data.get('syntax', 'text')
                expiration = data.get('expiration', 'never')
                
                if not content.strip(): response = "ERROR: Content cannot be empty"
                
                paste_id = str(uuid.uuid4())[:8]
                expires_at = get_expiration_date(expiration)
                
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()
                cursor.execute('INSERT INTO pastes (id, title, content, syntax_highlighting, expires_at) VALUES (?, ?, ?, ?, ?)', (paste_id, title, content, syntax, expires_at))
                conn.commit()
                conn.close()
                
                result = {'id': paste_id, 'title': title, 'syntax': syntax, 'expires_at': expires_at.isoformat() if expires_at else None, 'url': f'/{paste_id}'}
                
                return json.dumps(result, default=str)
                
            except json.JSONDecodeError: response = "ERROR: Invalid JSON format"
            except Exception as e: response = f"ERROR: {str(e)}"

            conn.sendall(response.encode())
        else: conn.sendall(b'ERROR: Invalid API\n')         
    except Exception as e:
        print(f'[SnakeBin-CLI] Error with {addr}: {e}')
        try: conn.sendall(f'ERROR: {str(e)}\n'.encode())
        except: pass
    finally:
        conn.close()

def process_read_command(paste_id):
    """Processa comando READ e retorna o conteúdo da paste"""
    if len(paste_id) != 8:
        return "ERROR: Invalid paste ID format (must be 8 characters)"
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT content, expires_at FROM pastes WHERE id = ?', (paste_id,))
        paste = cursor.fetchone()
        conn.close()
        
        if not paste:
            return "ERROR: Paste not found"
        
        expires_at = paste[1]
        if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
            return "ERROR: This paste has expired"
        
        return paste[0]  # Retorna apenas o conteúdo
        
    except Exception as e:
        return f"ERROR: {str(e)}"

def process_info_command(paste_id):
    """Processa comando INFO e retorna informações da paste em JSON"""
    if len(paste_id) != 8:
        return "ERROR: Invalid paste ID format (must be 8 characters)"
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, title, content, syntax_highlighting, created_at, expires_at FROM pastes WHERE id = ?', (paste_id,))
        paste = cursor.fetchone()
        conn.close()
        
        if not paste:
            return "ERROR: Paste not found"
        
        expires_at = paste[5]
        if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
            return "ERROR: This paste has expired"
        
        paste_data = {
            'id': paste[0],
            'title': paste[1],
            'content': paste[2],
            'syntax': paste[3],
            'created_at': paste[4],
            'expires_at': expires_at
        }
        
        return json.dumps(paste_data, default=str)
        
    except Exception as e:
        return f"ERROR: {str(e)}"

def connect_snake_cli(host='0.0.0.0', port=31523):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f'[SnakeBin-CLI] Server listening on {host}:{port}')

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_snake_cli, args=(conn, addr), daemon=True).start()

# Reader API
# |
@app.route("/api/json", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def info_json():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    return jsonify({
        "address": client_ip,
        "port": request.environ.get('REMOTE_PORT'),
        "agent": request.headers.get('User-Agent'),
        "method": request.method,
    })
# |
@app.route("/api/ip")
def ip_only():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    return Response(client_ip, mimetype='text/plain')
# |
@app.route("/api/ua")
def user_agent_only():
    user_agent = request.headers.get('User-Agent')
    return Response(user_agent, mimetype='text/plain')
# |
@app.route("/api/headers")
def headers_plaintext():
    headers = ""
    for key, value in request.headers.items():
        headers += f"{key}: {value}\n"
    return Response(headers, mimetype='text/plain')
# |
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
# |
@app.route("/api/versions")
def get_versions():
    data = load_versions()
    return jsonify(data)
# |
@app.route("/api/versions/downloads")
def get_downloads():
    data = load_versions()
    return jsonify(data.get("downloads", []))
# |
@app.route("/api/versions/news")
def get_news():
    data = load_versions()
    return jsonify(data.get("news", []))


if __name__ == '__main__':
    init_db()
    threading.Thread(target=start_tcp_server, daemon=True).start()
    threading.Thread(target=connect_snake_cli, daemon=True).start() 
    app.run(host='127.0.0.1', port=10141, debug=False, use_reloader=False)
 