# WebProxy CLI

A **web-panel with an interactive terminal** to manage reverse TCP connections via browser.
The system allows remote clients to connect to the server through **TCP**, while an operator can interact with them through **/cli/** in the browser.

---

## 🌐 Address

* **Web Panel:**
  [`http://opentty.xyz/cli/`](http://opentty.xyz/cli/)

* **TCP Bind Server:**
  `opentty.xyz:4096`

---

## 🚀 How it Works

1. A **TCP client** connects to the server at `opentty.xyz:4096`.

   * It provides a password upon connection.
   * It receives back a **unique session ID** (`conn_id`).

2. The operator accesses `http://opentty.xyz/cli/` in the browser.

   * Enters the `conn_id` and the corresponding password.
   * If approved, an **interactive web terminal** opens.

3. The panel uses **long polling** (`/cli/receive`) to display client output in real time.

   * Commands are sent via `/cli/send`.
   * Active sessions are controlled via `/cli/session`.

---

## 🖥️ Screens

### 🔑 Login

* URL: `/cli/`
* Fields:

  * **Connection ID**
  * **Password**

### 💻 Terminal

* URL: `/cli/terminal`
* Features:

  * Console with history
  * Command input
  * **Clear** button
  * **Disconnect** button
  * Active session indicator

---

## 📡 Main Endpoints

### Web CLI

* `GET /cli/` → Login page
* `POST /cli/login` → Session authentication
* `GET /cli/terminal` → Web Terminal
* `POST /cli/send` → Send commands
* `GET /cli/receive` → Receive output (long polling)
* `GET /cli/session` → Session status

### Utility API

* `GET /api/json` → Returns IP, port, agent, and method
* `GET /api/ip` → IP only
* `GET /api/ua` → User-Agent only
* `GET /api/headers` → HTTP headers
---

## ⚙️ Requirements

* **Python 3.9+**
* Libraries:

  * `flask`
  * `flask_cors`

---

## 💻 Using with OpenTTY

You can use this to access your control your OpenTTY in dumbphones with only support for GPRS _no local WI-FI support_.
**Note:** It requires OpenTTY 1.17 or newer with **Lua**

1. Download `proxy.lua` script:

    * Package **WebProxy** at _Yang Package Manager_
    * With curl `curl -o shprxy opentty.xyz/apps/net/proxy.lua`

2. Run Lua Script:

    * `shprxy [password]`
    * It prints `WebProxy ID: [id]` use **id** and password to connect in [WebPanel](http://opentty.xyz/cli/)

---

## ▶️ Running Locally

Clone the repository and run the Flask + TCP server:

```bash
git clone http://github.com/mrlima4095/pproxy.git
cd pproxy

pip install -r requirements.txt

python app.py
```

* Web: `http://127.0.0.1:10141/cli/`
* TCP: `127.0.0.1:4096`

---

## 📜 License

This project is part of **OpenTTY**.
Free to use for study purposes, with credit to the author.
