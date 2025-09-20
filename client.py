import socket
import subprocess
import threading

def receive_loop(sock, conn_id):
    try:
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    print("🔌 Conexão encerrada pelo servidor.")
                    break
                command = data.decode().strip()
                print(f"\n📥 Comando recebido: {command}")

                # Executa o comando no shell
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                output = result.stdout + result.stderr
                if not output:
                    output = "[sem saída]\n"

                print(f"📤 Enviando resposta de {len(output)} bytes\n")
                sock.sendall(output.encode())

            except Exception as e:
                error_msg = f"Erro ao executar comando: {e}\n"
                sock.sendall(error_msg.encode())
    except Exception as e:
        print(f"[ERRO] {e}")
    finally:
        sock.close()

def main():
    host = 'opentty.xyz'
    port = 4096

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # Espera a string 'Password:'
    data = sock.recv(1024).decode()
    if not data.startswith("Password:"):
        print("❌ Servidor não pediu senha. Encerrando.")
        return

    print(data, end='')  # Mostra 'Password:'
    password = input()
    sock.sendall((password + '\n').encode())

    # Recebe ID da conexão
    conn_id_msg = sock.recv(1024).decode()
    print(conn_id_msg.strip())

    conn_id = conn_id_msg.strip().split()[-1]  # assume que último token é o ID
    print(f"🔗 ID da conexão: {conn_id}")

    print("🔄 Aguardando comandos do servidor...\n")
    receive_loop(sock, conn_id)

if __name__ == "__main__":
    main()