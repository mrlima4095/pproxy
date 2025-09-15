import os
import sys
import socket
import threading
import io
import contextlib


class Application:
    def __init__(self, host="0.0.0.0", port=10143):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(31522)

        print(f"[+] Listening at port {port}")

        while True:
            client_sock, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(client_sock, addr))
            thread.start()

    def handle_client(self, client_socket, addr):
        print(f"[+] {addr[0]} connected")
        ENV = {}
        try:
            while True:
                payload = client_socket.recv(4096).decode('utf-8')
                if not payload:
                    break

                print(f"[+] {addr[0]} -> {payload}")

                output = io.StringIO()
                try:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                        exec(payload, ENV)
                except Exception as e:
                    output.write(str(e) + "\n")

                result = output.getvalue()

                client_socket.send(result.encode('utf-8'))

        finally:
            print(f"[-] {addr} disconnected")
            client_socket.close()


if __name__ == "__main__":
    if os.geteuid() == 0:
        print("[-] Execution as root is blocked for security reasons.")
        sys.exit(1)

    Application()