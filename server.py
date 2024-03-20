import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()
port = 12345  


server_socket.bind((host, port))


server_socket.listen(5)

while True:
    client_socket, addr = server_socket.accept()
    data = client_socket.recv(1024)
    print(f"[*] Received raw data from client: {data}")

    print('Got connection from', addr)
    client_socket.send(b'Thank you for connecting')
    client_socket.close()