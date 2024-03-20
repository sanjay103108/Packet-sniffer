# import socket
# import ssl

# # Define the server's IP address and port
# SERVER_HOST = '172.20.10.2'
# SERVER_PORT = 12345
# CERTFILE = 'server.crt'  # Path to your client certificate file
# KEYFILE = 'server.key'   # Path to your client private key file

# # Create a socket object
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# # Wrap the socket with SSL
# ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
# ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
# client_socket_ssl = ssl_context.wrap_socket(client_socket, server_hostname=SERVER_HOST)

# # Connect to the server
# client_socket_ssl.connect((SERVER_HOST, SERVER_PORT))
# print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")

# # Send raw data to the server
# data = b"Raw data from client!"
# client_socket_ssl.sendall(data)
# print(f"[*] Sent raw data to server: {data.decode()}")

# # Close the connection
# client_socket_ssl.close()
import socket


SERVER_HOST = '192.168.157.90'
SERVER_PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


client_socket.connect((SERVER_HOST, SERVER_PORT))
print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")


message = "Non-encoded raw data from client!"


data = message.encode('utf-8')


client_socket.sendall(data)
print(f"[*] Sent raw data to server: {message}")


client_socket.close()
