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
JSON_FILE = "/var/www/opentty/assets/root/web.json"
app.secret_key = 'segredo_super_seguro'
CORS(app)

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
    init_db()
    threading.Thread(target=start_tcp_server, daemon=True).start()
    threading.Thread(target=connect_snake_cli, daemon=True).start() 
    app.run(host='127.0.0.1', port=10141, debug=False, use_reloader=False)
 