import socket
import ssl

# Define the server's IP address and port
SERVER_HOST = '192.168.157.131'
SERVER_PORT = 12345
CERTFILE = 'server.crt'  # Path to your server certificate file
KEYFILE = 'server.key'   # Path to your server private key file

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((SERVER_HOST, SERVER_PORT))

# Listen for incoming connections
server_socket.listen(1)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

# Wrap the socket with SSL
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
server_socket_ssl = ssl_context.wrap_socket(server_socket, server_side=True)

# Accept a client connection
client_socket, client_address = server_socket_ssl.accept()
print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")

# Receive raw data from the client
data = client_socket.recv(1024)
print(f"[*] Received raw data from client: {data.decode()}")

# Close the connection
client_socket.close()
server_socket_ssl.close()