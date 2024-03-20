import socket
import ssl

def client():
    server_host ='192.168.157.90'  
    server_port = 12345       
    ssl_certfile = 'server.crt'
    ssl_keyfile = 'server.key'
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=ssl_certfile, keyfile=ssl_keyfile)
    ssl_client_socket = ssl_context.wrap_socket(client_socket, server_hostname=server_host)

    ssl_client_socket.connect((server_host, server_port))
    print("Connected to server over SSL")

    message = "Hello, server! This is a message from the SSL client."
    ssl_client_socket.send(message.encode())
    print("Message sent to server:", message)

    response = ssl_client_socket.recv(1024).decode()
    print("Response from server:", response)

    ssl_client_socket.close()

def main():
    client()

if __name__ == "_main_":
    main()

# import socket
# import ssl

# SERVER_HOST = '192.168.157.90'
# SERVER_PORT = 12345
# CERTFILE = 'server.crt'  
# KEYFILE = 'server.key'  

# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
# ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
# ssl_client_socket = ssl_context.wrap_socket(client_socket,server_hostname=SERVER_HOST)

# ssl_client_socket.connect((SERVER_HOST, SERVER_PORT))
# print("Connected to server over SSL")

# message = "Hello, server! This is a message from the SSL client."
# ssl_client_socket.send(message.encode())
# print("Message sent to server:", message)

# response = ssl_client_socket.recv(1024).decode()
# print("Response from server:", response)

# ssl_client_socket.close()